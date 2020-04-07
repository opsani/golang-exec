//
// Copyright (c) 2019 Stefaan Coussement
// MIT License
//
// more info: https://github.com/stefaanc/golang-exec
//
package ssh

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/stefaanc/golang-exec/script"
)

//------------------------------------------------------------------------------

type Connection struct {
	Type     string // must be "ssh"
	Host     string
	Port     uint16
	User     string
	Password string
	Insecure bool
}

type Error struct {
	script   *script.Script
	command  string
	exitCode int
	err      error
}

type Runner struct {
	script  *script.Script
	command string
	client  *ssh.Client
	session *ssh.Session
	running bool

	exitCode int
}

//------------------------------------------------------------------------------

func (e *Error) Script() *script.Script { return e.script }
func (e *Error) Command() string        { return e.command }
func (e *Error) ExitCode() int          { return e.exitCode }
func (e *Error) Error() string          { return e.err.Error() }
func (e *Error) Unwrap() error          { return e.err }

//------------------------------------------------------------------------------

func New(connection interface{}, s *script.Script, arguments interface{}) (*Runner, error) {
	if s.Error != nil {
		return nil, &Error{
			script:   s,
			exitCode: -1,
			err:      fmt.Errorf("[golang-exec/runner/ssh/New()] script failed to parse: %#w\n", s.Error),
		}
	}

	scriptReader, err := s.NewReader(arguments)
	if err != nil {
		return nil, &Error{
			script:   s,
			exitCode: -1,
			err:      fmt.Errorf("[golang-exec/runner/ssh/New()] cannot create stdin reader: %#w\n", err),
		}
	}
	var script string
	if b, err := ioutil.ReadAll(scriptReader); err == nil {
		script = string(b)
	}

	c := toConnection(connection)
	r := new(Runner)
	r.script = s
	r.command = s.Command() + script

	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	config := &ssh.ClientConfig{
		User: c.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Password),
		},
	}
	if c.Insecure {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		f, err := homedir.Expand("~/.ssh/known_hosts")
		if err != nil {
			return nil, &Error{
				script:   s,
				exitCode: -1,
				err:      fmt.Errorf("[golang-exec/runner/ssh/New()] cannot find home directory of current user: %#w\n", err),
			}
		}

		hostKeyCallback, err := knownhosts.New(f)
		if err != nil {
			return nil, &Error{
				script:   s,
				exitCode: -1,
				err:      fmt.Errorf("[golang-exec/runner/ssh/New()] cannot access 'known_hosts'-file: %#w\n", err),
			}
		}
		config.HostKeyCallback = hostKeyCallback
	}

	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, &Error{
			script:   s,
			exitCode: -1,
			err:      fmt.Errorf("[golang-exec/runner/ssh/New()] cannot dial host: %#w\n", err),
		}
	}
	r.client = client

	session, err := client.NewSession()
	if err != nil {
		return nil, &Error{
			script:   s,
			exitCode: -1,
			err:      fmt.Errorf("[golang-exec/runner/ssh/New()] cannot open session: %#w\n", err),
		}
	}
	r.session = session
	// r.session.Stdin = os.Stdin

	return r, nil
}

func toConnection(connection interface{}) *Connection {
	c := new(Connection)

	v := reflect.Indirect(reflect.ValueOf(connection))
	if v.Kind() == reflect.Struct {
		c.Type = v.FieldByName("Type").String()
		c.Host = v.FieldByName("Host").String()
		c.Port = uint16(v.FieldByName("Port").Uint())
		c.User = v.FieldByName("User").String()
		c.Password = v.FieldByName("Password").String()
		c.Insecure = v.FieldByName("Insecure").Bool()
	} else if v.Kind() == reflect.Map {
		iter := v.MapRange()
		for iter.Next() {
			switch iter.Key().String() {
			case "Type":
				c.Type = iter.Value().String()
			case "Host":
				c.Host = iter.Value().String()
			case "Port":
				p, err := strconv.ParseUint(iter.Value().String(), 10, 16)
				if err != nil {
					p = 0
				}
				c.Port = uint16(p)
			case "User":
				c.User = iter.Value().String()
			case "Password":
				c.Password = iter.Value().String()
			case "Insecure":
				b, err := strconv.ParseBool(strings.ToLower(iter.Value().String()))
				if err != nil {
					b = false
				}
				c.Insecure = b
			}
		}
	}

	return c
}

//------------------------------------------------------------------------------

func (r *Runner) SetStdoutWriter(stdout io.Writer) {
	r.session.Stdout = stdout
}

func (r *Runner) SetStderrWriter(stderr io.Writer) {
	r.session.Stderr = stderr
}

func (r *Runner) StdoutPipe() (io.Reader, error) {
	reader, err := r.session.StdoutPipe()
	if err != nil {
		r.exitCode = -1
		return nil, &Error{
			script:   r.script,
			exitCode: r.exitCode,
			err:      fmt.Errorf("[golang-exec/runner/ssh/StdoutPipe()] cannot create stdout reader: %#w\n", err),
		}
	}

	return reader, nil
}

func (r *Runner) StderrPipe() (io.Reader, error) {
	reader, err := r.session.StderrPipe()
	if err != nil {
		r.exitCode = -1
		return nil, &Error{
			script:   r.script,
			exitCode: r.exitCode,
			err:      fmt.Errorf("[golang-exec/runner/ssh/StderrPipe()] cannot create stderr reader: %#w\n", err),
		}
	}

	return reader, nil
}

func (r *Runner) Run() error {
	modes := ssh.TerminalModes{
		ssh.ECHOCTL:       0,
		ssh.ECHO:          1,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// stdin, err := r.session.StdinPipe()
	// if err != nil {
	// 	return fmt.Errorf("Unable to setup stdin for session: %v", err)
	// }
	// go io.Copy(stdin, os.Stdin)

	// stdout, err := r.session.StdoutPipe()
	// if err != nil {
	// 	return fmt.Errorf("Unable to setup stdout for session: %v", err)
	// }
	// go io.Copy(os.Stdout, stdout)

	// stderr, err := r.session.StderrPipe()
	// if err != nil {
	// 	return fmt.Errorf("Unable to setup stderr for session: %v", err)
	// }
	// go io.Copy(os.Stderr, stderr)

	// r.session.Stdout = os.Stdout
	// r.session.Stderr = os.Stderr
	r.session.Stdin = os.Stdin
	fileDescriptor := int(os.Stdin.Fd())
	if terminal.IsTerminal(fileDescriptor) {
		originalState, err := terminal.MakeRaw(fileDescriptor)
		if err != nil {
			return err
		}
		defer terminal.Restore(fileDescriptor, originalState)

		termWidth, termHeight, err := terminal.GetSize(fileDescriptor)
		if err != nil {
			return err
		}

		err = r.session.RequestPty("xterm-256color", termHeight, termWidth, modes)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Running command: %v", r.command)
	err := r.session.Run(r.command)
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			r.exitCode = exitErr.Waitmsg.ExitStatus()
			return &Error{
				script:   r.script,
				command:  r.command,
				exitCode: r.exitCode,
				err:      fmt.Errorf("[golang-exec/runner/ssh/Run()] runner failed: %#w\n", err),
			}
		} else {
			r.exitCode = -1
			return &Error{
				script:   r.script,
				command:  r.command,
				exitCode: r.exitCode,
				err:      fmt.Errorf("[golang-exec/runner/ssh/Run()] cannot execute runner: %#w\n", err),
			}
		}
	}

	r.exitCode = 0
	return nil
}

func (r *Runner) Start() error {
	err := r.session.Start(r.command)
	if err != nil {
		r.exitCode = -1
		return &Error{
			script:   r.script,
			command:  r.command,
			exitCode: r.exitCode,
			err:      fmt.Errorf("[golang-exec/runner/ssh/Start()] cannot start runner: %#w\n", err),
		}
	}
	r.running = true

	return nil
}

func (r *Runner) Wait() error {
	err := r.session.Wait()
	r.running = false
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			r.exitCode = exitErr.Waitmsg.ExitStatus()
		} else {
			r.exitCode = -1
		}
		return &Error{
			script:   r.script,
			command:  r.command,
			exitCode: r.exitCode,
			err:      fmt.Errorf("[golang-exec/runner/ssh/Wait()] runner failed: %#w\n", err),
		}
	}

	r.exitCode = 0
	return nil
}

func (r *Runner) Close() error {
	if r.running {
		_ = r.session.Signal(ssh.SIGTERM)
	}

	if r.session != nil {
		_ = r.session.Close()
	}

	if r.client != nil {
		r.client.Close()
	}

	return nil
}

func (r *Runner) ExitCode() int {
	return r.exitCode
}

//------------------------------------------------------------------------------

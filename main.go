package main

import (
	"flag"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const NoValue = "NO_VALUE"

var (
	host string
	user string
	password string
	port int

	sshSession *ssh.Session
)

func checkArgs() bool {
	hostOK := strings.TrimSpace(host) != `` && host != NoValue
	userOK := strings.TrimSpace(user) != `` && user != NoValue
	passwordOK := strings.TrimSpace(password) != `` && password != NoValue
	portOK := port > 0 && port < 65535

	return hostOK && userOK && passwordOK && portOK
}

func connect() error {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: 30 * time.Second,
	}
	hostPort := host + ":" + strconv.Itoa(port)

	connection, err := ssh.Dial("tcp", hostPort, sshConfig)
	if err != nil {
		return err
	}
	sshSession, err = connection.NewSession()
	if err != nil {
		return err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:  0, //disable echoing
		ssh.TTY_OP_ISPEED: 14440, //input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14440, //output speed = 14.4kbaud
	}
	if err := sshSession.RequestPty("xterm", 80, 40, modes); err != nil {
		err = sshSession.Close()
		return err
	}

	stdin, err := sshSession.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := sshSession.StderrPipe()
	if err != nil {
		return err
	}

	go io.Copy(stdin, os.Stdin)
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	return nil
}

func main() {
	flag.StringVar(&host, "host", NoValue, "Server FQDN to connect to")
	flag.StringVar(&user, "user", NoValue, "User to connect with")
	flag.StringVar(&password, "password", NoValue, "Password to connect with")
	flag.IntVar(&port, "port", 22, "Custom port if any")

	flag.Parse()

	paramsOK := checkArgs()

	if !paramsOK {
		log.Fatal("Invalid params")
	}

	connectionError := connect()
	if connectionError != nil {
		log.Fatal(connectionError)
	}

	runError := sshSession.Run("ls -al $HOME && cat $HOME/go-go-go")


	if runError != nil {
		log.Fatalf("Failed to run %s", runError)
	}
}

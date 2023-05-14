package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/sevlyar/go-daemon"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Server struct {
	listener net.Listener
	keyring  agent.Agent
	session  string
	folderId string
	socket   string
}

type Item struct {
	Object string `json:"string"`
	Id     string `json:"id"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"fields"`
	Attachments []struct {
		Id       string `json:"id"`
		FileName string `json:"fileName"`
		Url      string `json:"url"`
	} `json:"attachments"`
}

type Folder struct {
	Object string `json:"object"`
	Id     string `json:"id"`
	Name   string `json:"name"`
}

func NewServer(socket string) *Server {
	session := os.Getenv("BW_SESSION")
	if session == "" {
		log.Fatal("error: BW_SESSION is empty\n")
	}
	var folders []*Folder
	searchFoldersOutput, err := exec.Command("bw", "list", "folders", "--search", "ssh-agent", "--session", session).Output()
	if err != nil {
		log.Fatalf("error: %v\n", err)
	}
	if err := json.Unmarshal(searchFoldersOutput, &folders); err != nil {
		log.Fatalf("error: %v\n", err)
	}
	if len(folders) != 1 {
		log.Fatalf("error: %d folders with the name %s found", len(folders), "ssh-agent")
	}
	s := &Server{
		keyring:  agent.NewKeyring(),
		session:  session,
		folderId: folders[0].Id,
		socket:   socket,
	}
	return s
}

func (s *Server) Open() {
	listener, err := net.Listen("unix", s.socket)
	if err != nil {
		log.Printf("error: %v\n", err)
		return
	}
	s.listener = listener
	if err := os.Chmod(s.socket, 0700); err != nil {
		log.Printf("error: %v\n", err)
		s.Close()
		return
	}
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) Start() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.Process(conn)
	}
}

func (s *Server) Process(conn net.Conn) {
	defer conn.Close()
	if err := agent.ServeAgent(s.keyring, conn); err != nil {
		log.Printf("error: %v\n", err)
	}
}

func (s *Server) AddKey() error {
	var items []*Item
	getItems, err := exec.Command("bw", "list", "items", "--folderid", s.folderId, "--session", s.session).Output()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(getItems, &items); err != nil {
		return err
	}
	getPrivateKey, err := exec.Command("bw", "get", "attachment", "--itemid", items[0].Id, items[0].Attachments[0].Id, "--raw", "--session", s.session).Output()
	if err != nil {
		return err
	}
	privateKey, err := ssh.ParseRawPrivateKey(getPrivateKey)
	if err != nil {
		return err
	}
	if err := s.keyring.Add(agent.AddedKey{
		PrivateKey: privateKey,
	}); err != nil {
		return err
	}
	return nil
}

func main() {
	kill := flag.Bool("k", false, "kill ssh-agent daemon")
	flag.Parse()
	daemon.AddFlag(daemon.BoolFlag(kill), syscall.SIGTERM)
	tempDir := os.TempDir()
	socket := filepath.Join(tempDir, "bw-ssh-agent.sock")
	cntxt := &daemon.Context{
		Umask:       027,
		PidFileName: filepath.Join(tempDir, "bw-ssh-agent.pid"),
	}
	if len(daemon.ActiveFlags()) > 0 {
		d, err := cntxt.Search()
		if err != nil {
			log.Fatalf("Unable to signal the daemon: %v", err)
		}
		daemon.SendCommands(d)
		return
	}
	if d, err := cntxt.Search(); d != nil {
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("SSH_AUTH_SOCK=%v;export SSH_AUTH_SOCK;\n", socket)
		fmt.Printf("SSH_AGENT_PID=%v;export SSH_AGENT_PID;\n", strconv.Itoa(d.Pid))
		return
	}
	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatalln(err)
	}
	if d != nil {
		fmt.Printf("SSH_AUTH_SOCK=%v;export SSH_AUTH_SOCK;\n", socket)
		fmt.Printf("SSH_AGENT_PID=%v;export BW_SSH_AGENT_PID;\n", strconv.Itoa(d.Pid))
		return
	}
	defer cntxt.Release()
	server := NewServer(socket)
	server.Open()
	close := make(chan struct{})
	shutdown(server, close)
	if err := server.AddKey(); err != nil {
		log.Fatalln(err)
	}
	go server.Start()
	if err := daemon.ServeSignals(); err != nil {
		log.Println(err)
	}
}

func shutdown(server *Server, close chan struct{}) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		interrupt := 0
		for {
			s := <-c
			switch s {
			case os.Interrupt:
				if interrupt == 0 {
					fmt.Println("Interrupt...")
					interrupt++
					continue
				}
			}
			break
		}
		if err := server.Close(); err != nil {
			log.Printf("error: %v\n", err)
		}
		close <- struct{}{}
	}()
}

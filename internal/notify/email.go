package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/CosmoTheDev/ctrlscan-agent/internal/config"
)

// EmailChannel sends notifications via SMTP.
type EmailChannel struct {
	cfg config.EmailNotifyConfig
}

// NewEmail creates an EmailChannel from cfg.
func NewEmail(cfg config.EmailNotifyConfig) *EmailChannel { return &EmailChannel{cfg: cfg} }

func (e *EmailChannel) Name() string { return "email" }
func (e *EmailChannel) IsConfigured() bool {
	return e.cfg.SMTPHost != "" && e.cfg.To != "" && e.cfg.From != ""
}

func (e *EmailChannel) Send(_ context.Context, evt Event) error {
	body := fmt.Sprintf("Subject: %s\r\nFrom: %s\r\nTo: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		evt.Title, e.cfg.From, e.cfg.To, evt.Body)
	if evt.URL != "" {
		body += "\n\n" + evt.URL
	}

	port := e.cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := fmt.Sprintf("%s:%d", e.cfg.SMTPHost, port)

	var auth smtp.Auth
	if e.cfg.Username != "" {
		auth = smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.SMTPHost)
	}

	if e.cfg.UseTLS {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: e.cfg.SMTPHost}) // #nosec G402 -- TLS config uses system defaults; ServerName is set for SNI
		if err != nil {
			return fmt.Errorf("email: TLS dial: %w", err)
		}
		defer conn.Close()
		client, err := smtp.NewClient(conn, e.cfg.SMTPHost)
		if err != nil {
			return err
		}
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
		if err := client.Mail(e.cfg.From); err != nil {
			return err
		}
		if err := client.Rcpt(e.cfg.To); err != nil {
			return err
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(wc, body)
		if err != nil {
			return err
		}
		return wc.Close()
	}

	return smtp.SendMail(addr, auth, e.cfg.From, []string{e.cfg.To}, []byte(strings.ReplaceAll(body, "\n", "\r\n")))
}

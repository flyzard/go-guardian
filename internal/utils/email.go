package utils

import (
	"fmt"
	"net/smtp"
	"strings"
)

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromAddress  string
	FromName     string
}

type Email struct {
	To      []string
	Subject string
	Body    string
	HTML    bool
}

// SendEmail sends an email using SMTP
func SendEmail(config EmailConfig, email Email) error {
	auth := smtp.PlainAuth("", config.SMTPUsername, config.SMTPPassword, config.SMTPHost)

	// Build message
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s <%s>\r\n", config.FromName, config.FromAddress))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(email.To, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", email.Subject))

	if email.HTML {
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	} else {
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	}

	msg.WriteString("\r\n")
	msg.WriteString(email.Body)

	// Send email
	addr := config.SMTPHost + ":" + config.SMTPPort
	return smtp.SendMail(addr, auth, config.FromAddress, email.To, []byte(msg.String()))
}

// SendVerificationEmail sends an email verification link
func SendVerificationEmail(config EmailConfig, to, token string) error {
	// In production, use proper base URL
	verifyURL := fmt.Sprintf("https://example.com/verify?token=%s", token)

	email := Email{
		To:      []string{to},
		Subject: "Verify your email address",
		Body: fmt.Sprintf(`
            <h2>Verify your email address</h2>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="%s">Verify Email</a></p>
            <p>This link will expire in 24 hours.</p>
        `, verifyURL),
		HTML: true,
	}

	return SendEmail(config, email)
}

// SendPasswordResetEmail sends a password reset link
func SendPasswordResetEmail(config EmailConfig, to, token string) error {
	resetURL := fmt.Sprintf("https://example.com/reset-password?token=%s", token)

	email := Email{
		To:      []string{to},
		Subject: "Reset your password",
		Body: fmt.Sprintf(`
            <h2>Reset your password</h2>
            <p>You requested to reset your password. Click the link below:</p>
            <p><a href="%s">Reset Password</a></p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
        `, resetURL),
		HTML: true,
	}

	return SendEmail(config, email)
}

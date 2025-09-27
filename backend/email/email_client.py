import smtplib
import imaplib
import email
from email.message import EmailMessage
import base64
from config import EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT, EMAIL_IMAP_SERVER, EMAIL_IMAP_PORT

class EmailClient:
    def __init__(self, email_addr, password,
                 smtp_server=EMAIL_SMTP_SERVER, smtp_port=EMAIL_SMTP_PORT,
                 imap_server=EMAIL_IMAP_SERVER, imap_port=EMAIL_IMAP_PORT):
        self.email_addr = email_addr
        self.password = password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.imap_server = imap_server
        self.imap_port = imap_port

    def send_email(self, to_addr, subject, body_bytes, attachment_bytes=None, attachment_name=None):
        """
        Send email with encrypted body and optional attachment (both bytes).
        """
        msg = EmailMessage()
        msg['From'] = self.email_addr
        msg['To'] = to_addr
        msg['Subject'] = subject

        # Body as base64 to ensure safe transport
        body_b64 = base64.b64encode(body_bytes).decode('ascii')
        msg.set_content(body_b64)

        if attachment_bytes and attachment_name:
            # Add attachment as base64
            msg.add_attachment(attachment_bytes, maintype='application',
                               subtype='octet-stream', filename=attachment_name)

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp_conn:
                smtp_conn.starttls()
                smtp_conn.login(self.email_addr, self.password)
                smtp_conn.send_message(msg)
        except Exception as e:
            print(f"SMTP send error: {e}")
            raise

    def fetch_unread_emails(self):
        """
        Fetch unread emails from inbox.
        Return list of dicts with keys: from, subject, body_bytes, attachments (list of tuples (name, bytes))
        """
        emails = []
        try:
            with imaplib.IMAP4_SSL(self.imap_server, self.imap_port) as imap_conn:
                imap_conn.login(self.email_addr, self.password)
                imap_conn.select('Sent')
                result, data = imap_conn.search(None, 'ALL')
                if result != 'OK':
                    print("IMAP search error")
                    return emails

                email_ids = data[0].split()
                for eid in email_ids:
                    res, msg_data = imap_conn.fetch(eid, '(RFC822)')
                    if res != 'OK':
                        continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    from_ = msg.get('From')
                    subject = msg.get('Subject')
                    body_bytes = b''
                    attachments = []

                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            disp = str(part.get('Content-Disposition'))
                            if ctype == 'text/plain' and 'attachment' not in disp:
                                # Body assumed base64 encoded
                                body_b64 = part.get_payload(decode=True)
                                if body_b64:
                                    try:
                                        body_bytes = base64.b64decode(body_b64)
                                    except Exception:
                                        body_bytes = body_b64
                            elif 'attachment' in disp:
                                att_name = part.get_filename()
                                att_data = part.get_payload(decode=True)
                                attachments.append((att_name, att_data))
                    else:
                        # Not multipart - single part email
                        body_b64 = msg.get_payload(decode=True)
                        try:
                            body_bytes = base64.b64decode(body_b64)
                        except Exception:
                            body_bytes = body_b64

                    emails.append({
                        'from': from_,
                        'subject': subject,
                        'body_bytes': body_bytes,
                        'attachments': attachments
                    })

                    # Mark as seen
                    imap_conn.store(eid, '+FLAGS', '\\Seen')
        except Exception as e:
            print(f"IMAP fetch error: {e}")

        return emails
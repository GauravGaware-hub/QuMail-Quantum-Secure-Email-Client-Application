# run_test.py

from email_service import EmailService

def main():
    email_service = EmailService()

    sender = "alice@example.com"
    recipient = "bob@example.com"
    message = "Hello Bob, this is a secret message from Alice."

    # Alice sends encrypted email to Bob
    email_package = email_service.send_email(sender, recipient, message)
    if not email_package:
        print("Sending email failed.")
        return

    # Bob receives and decrypts the email
    decrypted_message = email_service.receive_email(email_package)
    if decrypted_message is None:
        print("Receiving email failed.")

if __name__ == "__main__":
    main()
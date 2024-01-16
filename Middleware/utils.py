import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
from models.user_model import UserOTP
from mongoengine.errors import ValidationError, NotUniqueError 
import random, time, string
from decouple import config


EMAIL_ADDRESS = config("EMAIL_ADDRESS")
EMAIL_PASSWORD = config("EMAIL_PASSWORD")
SMTP_SERVER = config("SMTP_SERVER")
SMTP_PORT = config("SMTP_PORT")

def generate_otp(length=6):
    # Generate a random OTP of the specified length
    otp = ''.join(random.choices(string.digits, k=length))
    return otp

# Define the generate_and_send_otp function here
def generate_and_send_otp(email: str, otp: str = None):
    try:
        # Generate OTP
        if otp is None:
            otp = generate_otp()  # Generate OTP if not provided
        print(f"Generated OTP: {otp}")  # Print the generated OTP for debugging

        # Calculate OTP expiry time (e.g., 10 minutes from now)
        expiry_time = datetime.now() + timedelta(minutes=3)

        # Create an UserOTP object
        otp_data = UserOTP(email=email, otp=otp, expiry_time=expiry_time)

        # Save the UserOTP object to the database
        otp_data.save()

        print("OTP saved to the database.")  # Print a message to indicate that the OTP was saved

        # Send OTP to the user's email
        send_email("OTP Subject", generate_otp, email)
        print("OTP sent to email.")  # Print a message to indicate that the OTP was sent

        return {
            "success": True,
            "message": "OTP sent successfully. Check your email for the OTP code.",
            "otp": otp  # Include the OTP in the response
        }
    except ValidationError as ve:
        print(f"Validation error when saving OTP: {ve}")
        return {
            "success": False,
            "message": "Validation error when saving OTP. Please check your data.",
        }
    except NotUniqueError as nue:
        print(f"Duplicate entry error when saving OTP: {nue}")
        return {
            "success": False,
            "message": "An OTP for this email already exists. Please try again later.",
        }
    except Exception as e:
        # Handle other errors here
        return {
            "success": False,
            "message": "Failed to save OTP. Please try again later.",
        }




def send_email(subject, message, to_email, attachment_path=None):
    try:
        # Create an SMTP connection
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Start a secure TLS connection
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  # Login to your email account

            msg = MIMEMultipart()
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = to_email  # Pass the 'to_email' parameter
            msg['Subject'] = subject

            # Attach the message
            msg.attach(MIMEText(message, 'plain'))

            # Attach an optional attachment
            if attachment_path:
                with open(attachment_path, 'rb') as file:
                    attachment = MIMEApplication(file.read(), Name='document.pdf')
                attachment['Content-Disposition'] = f'attachment; filename="document.pdf"'
                msg.attach(attachment)

            # Send the email
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

            print("Email sent successfully.")
            return True
    except Exception as e:
        # Handle errors here and print the error message
        if isinstance(e, smtplib.SMTPException):
            print(f"SMTP error: {str(e)}")
        elif isinstance(e, FileNotFoundError):
            print(f"File not found: {attachment_path}")
        else:
            print(f"Error sending email: {str(e)}")
        return False




def send_email_with_retry(subject, message, to_email, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            send_email(subject, message, to_email)
            print("Email sent successfully.")
            return True
        except smtplib.SMTPException as e:
            print(f"SMTP error: {str(e)}")
            retries += 1
            if retries < max_retries:
                print(f"Retrying in 5 seconds... (Attempt {retries}/{max_retries})")
                time.sleep(5)
    print("Max retries reached. Email sending failed.")
    return False

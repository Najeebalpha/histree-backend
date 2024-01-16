from models.user_model import UserModel, UserCreate, UserLogin, UserOTP
from werkzeug.security import check_password_hash
from fastapi import HTTPException, status, Request
from Middleware.utils import generate_and_send_otp, send_email
from models.user_model import UserCreate, OTPValidationRequest
from datetime import datetime


# Define a UserController class
class UserController:
    @staticmethod
    def signup(user_create: UserCreate):
        try:
            # Check if a user with the provided email already exists
            existing_user = UserModel.objects(email=user_create.email).first()

            if existing_user:
                print("User already exists.")  # Add this line for debugging
                return {
                    "success": False,
                    "userMessage": "Email already registered",
                }

            # Generate and send OTP
            result = generate_and_send_otp(
                user_create.email)  # Generate and send OTP

            if result["success"]:
                print("OTP sent successfully.")  # Add this line for debugging

                # Now, send a welcome email to the new user
                welcome_message = "Welcome to our platform! Your OTP is: " + \
                    result["otp"]  # Include the OTP
                send_email("Welcome to Our Platform",
                           welcome_message, user_create.email)

                return {
                    "success": True,
                    "userMessage": "OTP has been sent to your email. Please verify.",
                    "user": {
                        "full_name": user_create.full_name,
                        "email": user_create.email,
                    }
                }
            else:
                # Add this line for debugging
                print(f"Error sending OTP: {result['message']}")
                return {
                    "success": False,
                    "userMessage": result["message"],
                }

        except Exception as e:
            # Handle errors here
            print(f"Error in signup: {str(e)}")  # Add this line for debugging
            raise HTTPException(
                status_code=500, detail="Internal Server Error")

    @staticmethod
    def login(user_login: UserLogin):
        try:
            email = user_login.email
            password = user_login.password

            # Find a user with the provided email
            user = UserModel.objects(email=email).first()

            if not user:
                # If no user is found, return an error response with status code 404
                return {"error": "Email not registered"}

            # Check if the provided password matches the stored hashed password
            if check_password_hash(user.password_hash, password):
                # If the password matches, return a success message response with status code 200
                return {
                    "success": True,
                    "Usermessage": "Login successful!! Welcome to Treehouse Home of history",
                    "user": {
                        "email": email}
                }

            else:
                # If the password doesn't match, return an error response with status code 401
                return {"error": "Invalid password"},
        except Exception as e:
            # Handle other exceptions and return an error response
            return {
                "error": "Error during login: " + str(e),
            }

    @staticmethod
    def validate_otp(otp_data: OTPValidationRequest):
        try:
            email = otp_data.email
            otp = otp_data.otp

            # Debugging
            print(f"Validating OTP for email: {email}, OTP: {otp}")

            # Query the database to find the OTP document
            otp_doc = UserOTP.objects(email=email, otp=otp).first()

            if not otp_doc:
                print("Invalid OTP or email.")  # Debugging
                return {
                    "success": False,
                    "userMessage": "Invalid OTP or email. Please try again.",
                }

            # OTP is valid, create a new user
            user_create = UserCreate(
                full_name="Full Name",  # Replace with user's full name
                email=email,  # Use the email provided during OTP validation
                password="Password",  # Replace with user's password
                gender="Gender"  # Replace with user's gender
            )

            # Create the new user
            new_user = UserModel.create_user(user_create)

            # Remove the OTP document from the database
            otp_doc.delete()

            print("User registered successfully.")  # Debugging
            return {
                "success": True,
                "userMessage": "User registered successfully.",
                "user": {
                    "full_name": new_user.full_name,
                    "email": new_user.email,
                }
            }

        except Exception as e:
            # Handle exceptions and return an error response
            # Debugging
            print(
                f"Error during OTP validation or user registration: {str(e)}")
            return {
                "success": False,
                "userMessage": "Failed to validate OTP or register user. Please try again later.",
            }

from bson.objectid import ObjectId
from typing import List
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from controllers.user_controller import UserController
from models.user_model import UserCreate, UserModel, UserLogin, HistoryCategoryModel, HistoricalStories, HistoryCategoryResponse, HistoricalStoryResponse, HistoricalStoriesbycategory, OTPValidationRequest
from mongoengine import connect
from jose import JWTError, jwt
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from pydantic import EmailStr
from decouple import config


# Define a logger for error handlingclear
logger = logging.getLogger(__name__)


# Create a FastAPI application instance
app = FastAPI()

# Configure the database connection to MongoDB
connect('familytree', host=config("MONGO_URI"))

SECRET_KEY = "SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing configurations

# Function to verify a password


def verify_password(plain_password, hashed_password):
    return check_password_hash(hashed_password, plain_password)

# Function to get the password hash


def get_password_hash(password):
    return generate_password_hash(password)

# Function to create an access token


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt


# Login for access token route
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        user = UserModel.objects(email=form_data.username).first()
        if not user or not verify_password(form_data.password, user.password_hash):
            raise HTTPException(
                status_code=400, detail="Incorrect username or password")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": form_data.username}, expires_delta=access_token_expires
        )

        return {"access_token": access_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES}
    except Exception as e:
        raise

# Function to verify a token


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Check the token's expiration
        exp_timestamp = payload.get("exp")
        if exp_timestamp is None or datetime.utcnow() > datetime.fromtimestamp(exp_timestamp):
            return None

        return payload
    except JWTError:
        return None


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Define your get_current_user function


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        # Decode the token using the secret key and algorithm
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract user information from the token (modify this to match your token content)
        user_id = payload.get("sub")

        return user_id

    except JWTError:
        raise HTTPException(
            status_code=401, detail="Could not validate credentials")


# delegating the sign up logic to the UserController, which handles exceptions and returns responses as needed.
@app.post('/users/signup')
async def signup(user_create: UserCreate):
    try:
        result = UserController.signup(user_create)
        print(f"Signup Result: {result}")  # Add this line for debugging
        return result
    except Exception as e:
        # Add this line for debugging
        print(f"Error in route handler: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post('/users/validate-otp')
async def validate_otp(otp_data: OTPValidationRequest):
    try:
        result = UserController.validate_otp(otp_data)
        return result
    except HTTPException as e:
        return {
            "success": False,
            "userMessage": str(e.detail),
        }
    except Exception as e:
        return {
            "success": False,
            "userMessage": "Failed to validate OTP. Please try again later.",
        }


# delegating the login logic to the UserController, which handles exceptions and returns responses as needed.
@app.post('/users/login')
async def login(user_login: UserLogin, current_user: str = Depends(get_current_user)):
    return UserController.login(user_login)


# Endpoint to fetch all historical categories
@app.get("/categories", response_model=List[HistoryCategoryResponse])
async def get_categories(current_user: str = Depends(get_current_user)):
    try:
        categories = HistoryCategoryModel.objects().all()
        return categories
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")


# Endpoint to list story names by category
@app.get("/stories-by-category/{category_id}", response_model=List[str])
async def list_story_names_by_category(category_id: str, str=Depends(get_current_user)):
    try:
        category = HistoryCategoryModel.objects(id=category_id).first()
        if category is None:
            raise HTTPException(status_code=404, detail="Category not found")

        # Define a projection to include only the 'name' field in the query
        projection = {"name": 1}

        stories = HistoricalStoriesbycategory.objects(
            category=category).only(*projection.keys())

        # Extract the names of stories in the selected category
        story_names = [story.name for story in stories]

        return story_names
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")


# Endpoint to get the details of a selected story by ID
@app.get("/story-details/{story_id}", response_model=HistoricalStoryResponse)
async def get_story_details(story_id: str, str=Depends(get_current_user)):
    try:
        # Find the story by its ID
        story = HistoricalStories.objects(id=story_id).first()

        if story is None:
            raise HTTPException(status_code=404, detail="Story not found")

        # Define the response data using the Pydantic model
        response_data = HistoricalStoryResponse(
            name=story.name,
            dob=story.dob,
            gender=story.gender,
            bio=story.bio,
            image_url=story.image_url,
            category=HistoryCategoryResponse(
                category=story.category.category,  # Access the category field
                description=story.category.description
            )
        )

        return response_data
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Import necessary modules and classes
from datetime import datetime, date
from pydantic import BaseModel
from mongoengine import Document, StringField, DateField, ListField, ReferenceField, URLField
from pydantic import BaseModel, validator
from werkzeug.security import generate_password_hash
from mongoengine.fields import DateTimeField
from typing import List, Optional








# Define a Pydantic model for creating users
class UserCreate(BaseModel):
    full_name: str
    email: str
    password: str 
    gender: str


# Define a MongoDB document model for users
class UserModel(Document):
    full_name = StringField(required=True)
    email = StringField(unique=True, required=True)
    password_hash = StringField(required=True)
    gender = StringField(required=True)
    created_at = DateTimeField()
    updated_at = DateTimeField()


    # Class method to create a new user
    @classmethod
    def create_user(cls, user_create: UserCreate):
        # Generate a password hash using Werkzeug
        password_hash = generate_password_hash(user_create.password)
        
        # Create a new user document with provided data
        user = cls(
            full_name=user_create.full_name,
            email=user_create.email,
            password_hash=password_hash,
            gender=user_create.gender  # Set the gender field


        )
    
        
        # Save the user document to the database
        user.save()
        
        # Return the created user document
        return user
    


# Pydantic model for creating  OTP document
class UserOTP(BaseModel):
    email: str
    otp: str
    expiry_time: datetime

class UserOTP(Document):
    email = StringField(required=True)
    otp = StringField(required=True)
    expiry_time = DateTimeField(required=True)

# Add OTPValidation model
class OTPValidationRequest(BaseModel):
    email: str
    otp: str



class UserLogin(BaseModel):
    email: str
    password: str




class HistoryCategoryModel(Document):
    category = StringField(required=True)
    description = StringField(required=True)



class HistoricalStories(Document):
    name = StringField(required=True)
    dob = DateField(required=True)
    gender = StringField(required=True)
    bio = StringField(required=True)
    image_url = URLField(required=True)
    category = ReferenceField('HistoryCategoryModel')  # Reference the HistoryCategoryModel

    meta = {'collection': 'historical_stories'}



class HistoryCategoryModel(Document):
    category = StringField(required=True)  # Rename the field from "name" to "category"
    description = StringField(required=True)

    meta = {
        'collection': 'history_category_model'  # Specify the collection name
    }


class HistoryCategoryResponse(BaseModel):
    category: str
    description: str


class HistoricalStoriesbycategory(Document):
    name = StringField(required=True)
    category = ReferenceField(HistoryCategoryModel)
    meta = {'collection': 'historical_stories'}


class HistoricalStoriesResponse(BaseModel):
    name: str
    category: str  




class HistoricalStoryResponse(BaseModel):
    name: str
    dob: date
    gender: str
    bio: str
    image_url: str
    category: HistoryCategoryResponse  





















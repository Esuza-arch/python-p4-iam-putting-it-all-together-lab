from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from flask_bcrypt import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from config import db

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    _password_hash = Column("password_hash", String, nullable=False)
    image_url = Column(String, default="https://www.example.com/default-image.jpg")
    bio = Column(String, default="")

    # Relationship with Recipe
    recipes = relationship("Recipe", backref="user", lazy=True)

    @property
    def password_hash(self):
        """Password hash is private and should not be directly accessed."""
        raise AttributeError("Password hash is not accessible")

    @password_hash.setter
    def password_hash(self, password):
        """Hash the password before storing it."""
        self._password_hash = generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        """Verify the password hash."""
        return check_password_hash(self._password_hash, password)


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    instructions = Column(String, nullable=False)
    minutes_to_complete = Column(Integer, nullable=False)

    user_id = Column(Integer, ForeignKey('users.id'))  # Foreign key to User model

    @validates('title')
    def validate_title(self, key, title):
        """Ensures that the title is not empty"""
        if not title:
            raise ValueError("Title is required.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        """Ensures that instructions are at least 50 characters long"""
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

    @validates('minutes_to_complete')
    def validate_minutes(self, key, minutes_to_complete):
        """Ensures that minutes_to_complete is a positive integer"""
        if minutes_to_complete <= 0:
            raise ValueError("Minutes to complete must be greater than 0.")
        return minutes_to_complete

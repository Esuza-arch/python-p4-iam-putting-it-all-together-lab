#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()

        if not data.get("username") or not data.get("password"):
            return {"error": "Username and password are required"}, 422

        hashed_password = generate_password_hash(data["password"])
        
        new_user = User(
            username=data["username"],
            password_hash=hashed_password,
            bio=data.get("bio", ""),
            image_url=data.get("image_url", "")
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            session["user_id"] = new_user.id  # Log user in
            return {
                "id": new_user.id,
                "username": new_user.username,
                "bio": new_user.bio,
                "image_url": new_user.image_url
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already exists"}, 400

class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)

        if user:
            return {
                "id": user.id,
                "username": user.username,
                "bio": user.bio,
                "image_url": user.image_url
            }, 200
        
        return {"error": "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()

        if not data.get("username") or not data.get("password"):
            return {"error": "Username and password required"}, 400

        user = User.query.filter_by(username=data["username"]).first()

        if user and check_password_hash(user.password_hash, data["password"]):
            session["user_id"] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "bio": user.bio,
                "image_url": user.image_url
            }, 200
        
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        if "user_id" not in session:
            return {"error": "Unauthorized"}, 401
        
        session.pop("user_id")
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = User.query.get(user_id)
        
        recipes = [{
            "id": recipe.id,
            "title": recipe.title,
            "instructions": recipe.instructions,
            "minutes_to_complete": recipe.minutes_to_complete
        } for recipe in user.recipes]

        return recipes, 200

    def post(self):
        user_id = session.get("user_id")

        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()

        if not data.get("title") or not data.get("instructions") or not isinstance(data.get("minutes_to_complete"), int):
            return {"error": "Invalid recipe data"}, 422

        new_recipe = Recipe(
            title=data["title"],
            instructions=data["instructions"],
            minutes_to_complete=data["minutes_to_complete"],
            user_id=user_id
        )

        db.session.add(new_recipe)
        db.session.commit()

        return {
            "id": new_recipe.id,
            "title": new_recipe.title,
            "instructions": new_recipe.instructions,
            "minutes_to_complete": new_recipe.minutes_to_complete
        }, 201

api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")

if __name__ == "__main__":
    app.run(port=5555, debug=True)


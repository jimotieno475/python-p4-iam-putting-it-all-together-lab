#!/usr/bin/env python3

from flask import request, session,jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
from werkzeug.security import generate_password_hash
class Signup(Resource):
    def post(self):
        json_data = request.get_json()

        try:
            # Hash the password
            hashed_password = generate_password_hash(json_data['password'], method='sha256')

            # Create a new User instance
            user = User(
                username=json_data['username'],
                password_hash=hashed_password,
                image_url=json_data['image_url'],
                bio=json_data['bio']
            )

            # Add the user to the database
            db.session.add(user)
            db.session.commit()

            return user.to_dict(), 201
        except IntegrityError as e:
            db.session.rollback()  # Rollback the transaction on IntegrityError
            return {'message': 'Username already exists'}, 422
        except Exception as e:
            print(e)  # Log the error for debugging
            return {'message': 'Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        # Check if 'user_id' key exists in the session
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        else:
            return {'message': 'User is not logged in'}, 401


class Login(Resource):
    def post(self):
        try:
            json_data = request.get_json()
            username = json_data['username']
            password = json_data['password']

            # Retrieve user by username
            user = User.query.filter_by(username=username).first()

            # Check if the user exists and authenticate the password
            if user and user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200

            return {'error': 'Invalid username or password'}, 401
        except Exception as e:
            print(e)  # Log the error for debugging
            return {'message': 'Unprocessable Entity'}, 422


class Logout(Resource):
    def delete(self):
        # Get the username from the JSON data
        username = request.get_json().get('username')

        # Check if the user is logged in
        if 'user_id' in session and session['user_id'] is not None:
            # Clear the user_id from the session
            session['user_id'] = None
            return {}, 204
        else:
            return {'message': 'User is not logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        # Check if the user is logged in
        if 'user_id' in session and session['user_id'] is not None:
            # User is logged in, retrieve and return recipes
            recipes = Recipe.query.all()
            recipes_data = [{'title': recipe.title, 'instructions': recipe.instructions, 'minutes_to_complete': recipe.minutes_to_complete, 'user': recipe.user.to_dict()} for recipe in recipes]

            return jsonify(recipes_data), 200
        else:
            # User is not logged in, return a 401 Unauthorized status
            return {'message': 'Unauthorized'}, 401

    def post(self):
        # Check if the user is logged in
        if 'user_id' in session and session['user_id'] is not None:
            # User is logged in, proceed with recipe creation
            json_data = request.get_json()

            # Extract recipe information from JSON data
            title = json_data.get('title')
            instructions = json_data.get('instructions')
            minutes_to_complete = json_data.get('minutes_to_complete')

            # Validate the recipe data
            if not (title and instructions and minutes_to_complete):
                return {'message': 'Title, instructions, and minutes_to_complete are required'}, 422

            # Create a new recipe instance
            new_recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id']
            )

            # Add the recipe to the database
            db.session.add(new_recipe)
            db.session.commit()

            # Return a JSON response with the created recipe and a 201 status code
            return jsonify({
                'title': new_recipe.title,
                'instructions': new_recipe.instructions,
                'minutes_to_complete': new_recipe.minutes_to_complete,
                'user': new_recipe.user.to_dict()
            }), 201
        else:
            # User is not logged in, return a 401 Unauthorized status
            return {'message': 'Unauthorized'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
import os
import sys
import json
import base64
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies, unset_jwt_cookies
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from dotenv import load_dotenv

load_dotenv()

# ... rest of the code ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

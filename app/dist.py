"""
Serves applications from the /dist directory
"""

from flask import Blueprint, request, send_from_directory, Response

from app import db
import os
from models import Credentials, Host

dist = Blueprint('dist', __name__, url_prefix='/dist')


@dist.route('/<filename>')
def serve_root(filename):
    return send_from_directory('dist', filename)


@dist.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        res = Response()
        res.headers['X-Content-Type-Options'] = '*'
        return res

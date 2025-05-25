"""
Need a better name for this:
this includes all self made scripts
"""

from flask import Blueprint, request, send_from_directory
import hh.utils
from app import db
import os
from models import Credentials, Host

custom = Blueprint('custom', __name__, url_prefix='/custom')


@custom.route('/<path:path>')
def custom_serve(path):
    current_folder = hh.utils.get_hh_folder()
    return send_from_directory(os.path.join(current_folder, 'app', 'custom'), path)

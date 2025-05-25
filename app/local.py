"""
Serves applications from the local (cwd) directory
"""

from flask import Blueprint, request, send_from_directory

import os

local = Blueprint('local', __name__, url_prefix='/local')


@local.route('/<path:path>')
def local_root(path):
    current_folder = os.getcwd()
    return send_from_directory(current_folder, path)

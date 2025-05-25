import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from queue import Queue

from pathlib import Path
from alembic.config import Config
from alembic import command

MIGRATION_DIR = os.path.join(Path(__file__).resolve().parent.parent, 'migrations')

db = SQLAlchemy()
migrate = Migrate(directory=MIGRATION_DIR)
nmap_queue = Queue()
nmap_store = {}


def create_app(cfg):
    app = Flask(__name__, instance_relative_config=True)

    # we use project based dbs
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'helpinghand.db')

    DB_EXISTS = os.path.exists(os.path.join(os.getcwd(), 'helpinghand.db'))

    app.config.from_object(cfg)
    db.init_app(app)

    # app.logger = log
    # DB Migrations (create and update tables)
    # migrate.init_app(app, db)
    migrate.init_app(app, db, render_as_batch=True)

    with app.app_context():
        db.create_all()

        # ONLY STAMP IF A NEW DB
        # db.create_all() will not stamp the alembic version
        # maybe i fixed it now?
        if not DB_EXISTS:
            cfg = os.path.join(Path(__file__).resolve().parent.parent, 'migrations', 'alembic.ini')
            alembic_cfg = Config(os.path.join(Path(__file__).resolve().parent.parent, 'migrations', 'alembic.ini'))
            alembic_cfg.set_main_option('script_location', MIGRATION_DIR)
            command.stamp(alembic_cfg, 'head')

        # upgrade schema
    with app.app_context():
        upgrade()

    from .dist import dist
    app.register_blueprint(dist)

    from .custom import custom
    app.register_blueprint(custom)

    from .upload import upload
    app.register_blueprint(upload)

    from .local import local
    app.register_blueprint(local)

    # so that we can access sqlalchemy outside view context
    app.app_context().push()

    return app

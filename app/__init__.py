from flask import Flask, redirect, url_for, flash, request
from flask_wtf.csrf import CSRFProtect, CSRFError
from .extensions import db, login_manager, migrate, mail
from flask_mail import Mail

csrf = CSRFProtect()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    csrf.init_app(app)
    mail.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

    from .routes import bp as main_routes
    app.register_blueprint(main_routes)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash("The form submission failed due to missing or invalid CSRF token.", "danger")
        return redirect(request.referrer or url_for('main.index'))

    with app.app_context():
        from .models import User, Form, Question, Response
        db.create_all()

    return app

@login_manager.user_loader
def load_user(user_id):
    from .models import User 
    return User.query.get(int(user_id))

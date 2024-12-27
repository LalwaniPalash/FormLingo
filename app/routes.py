import csv 
import openpyxl
from io import StringIO, BytesIO
from fuzzywuzzy import fuzz, process
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, Response, make_response, current_app
from flask_login import login_user, login_required, logout_user, current_user
import json
import os
import pyotp
from flask_mail import Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Form, Question, Response
from .forms import LoginForm, RegisterForm, ForgotPasswordForm
from .extensions import db
from .translation import translate_text, translate_ans
from .languages import supported_languages
from .utils import generate_qr_code, allowed_file, mail, send_password_reset_email, verify_reset_token, send_notification_email

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    return render_template('index.html', title="Home")

@bp.route('/about')
def about():
    return render_template('about.html', title="About Us")

@bp.route('/contact', methods=['GET'])
def contact():
    return render_template('contact.html', title="Contact Us")

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            if user.two_factor_enabled:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('main.verify_2fa'))
            else:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title="Login", form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('main.index'))
        else:
            flash('No account found with the given email', 'info')
    return render_template('forgot_password.html', title="Forgot Password", form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = None
    for u in User.query.all():
        if verify_reset_token(token, u):
            user = u
            break

    if not user:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('main.forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('main.reset_password', token=token))

        user.password = generate_password_hash(new_password)
        user.password_reset_token = None
        db.session.commit()
        flash('Your password has been reset successfully. You can now log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('reset_password.html', title="Reset Password", token=token)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', title="Register", form=form)

@bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'created_on')
    sort_order = request.args.get('sort_order', 'desc')

    forms_query = Form.query.filter_by(user_id=current_user.id)
    all_forms = forms_query.all()

    if search_query:
        form_names = [form.name for form in all_forms]
        matched_names = process.extract(search_query, form_names, limit=10, scorer=fuzz.partial_ratio)
        matched_form_names = [name for name, score in matched_names if score > 60]

        forms = [form for form in all_forms if form.name in matched_form_names]
    else:
        forms = all_forms

    if sort_by and hasattr(Form, sort_by):
        if sort_order == 'asc':
            forms = sorted(forms, key=lambda x: getattr(x, sort_by))
        else:
            forms = sorted(forms, key=lambda x: getattr(x, sort_by), reverse=True)

    return render_template(
        'dashboard.html',
        title="Dashboard",
        forms=forms,
        search_query=search_query,
        sort_by=sort_by,
        sort_order=sort_order
    )

@bp.route('/create-form', methods=['GET', 'POST'])
@login_required
def create_form():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        questions = request.form.getlist('questions[]')
        question_types = request.form.getlist('question_types[]')
        options_list = request.form.getlist('options[]')

        new_form = Form(name=name, description=description, user_id=current_user.id)
        new_form.generate_unique_token()
        db.session.add(new_form)
        db.session.flush()

        for i in range(len(questions)):
            question = Question(
                form_id=new_form.id,
                question_text=questions[i],
                question_type=question_types[i],
                options=options_list[i] if question_types[i] in ['mcq', 'dropdown'] else None
            )
            db.session.add(question)

        db.session.commit()
        flash('Form created successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('create_form.html', title="Create Form")

@bp.route('/edit-form/<int:form_id>', methods=['GET', 'POST'])
@login_required
def edit_form(form_id):
    form_to_edit = Form.query.filter_by(id=form_id, user_id=current_user.id).first()

    if not form_to_edit:
        flash('Form not found or access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        form_to_edit.name = request.form['name']
        form_to_edit.description = request.form['description']
        questions = request.form.getlist('questions[]')
        question_types = request.form.getlist('question_types[]')
        options_list = request.form.getlist('options[]')

        for question in form_to_edit.questions:
            db.session.delete(question)

        for i in range(len(questions)):
            updated_question = Question(
                form_id=form_to_edit.id,
                question_text=questions[i],
                question_type=question_types[i],
                options=options_list[i] if question_types[i] in ['mcq', 'dropdown'] else None
            )
            db.session.add(updated_question)

        db.session.commit()
        flash('Form updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    existing_questions = [
        {
            'text': question.question_text,
            'type': question.question_type,
            'options': question.options
        }
        for question in form_to_edit.questions
    ]

    return render_template(
        'create_form.html',
        title="Edit Form",
        form=form_to_edit,
        edit_mode=True,
        questions=existing_questions
    )

@bp.route('/delete-form/<int:form_id>', methods=['POST'])
@login_required
def delete_form(form_id):
    form_to_delete = Form.query.filter_by(id=form_id, user_id=current_user.id).first()

    if not form_to_delete:
        flash('Form not found or access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        Response.query.filter_by(form_id=form_id).delete()
        Question.query.filter_by(form_id=form_id).delete()
        db.session.delete(form_to_delete)
        db.session.commit()

        flash('Form deleted successfully!', 'success')
    except Exception as e:
        current_app.logger.error(f"Error deleting form: {e}")
        flash('An error occurred while deleting the form.', 'danger')

    return redirect(url_for('main.dashboard'))

@bp.route('/form/<public_token>', methods=['GET', 'POST'])
def submit_form(public_token):
    form = Form.query.filter_by(public_token=public_token).first_or_404()
    detected_language = request.headers.get('Accept-Language', 'en').split(',')[0]
    language = request.args.get('lang', detected_language)
    languages = supported_languages

    if request.method == 'POST':
        responses = {}

        for question in form.questions:
            if question.question_type == 'file':
                file = request.files.get(str(question.id))
                if file and file.filename != '':
                    if allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        responses[question.id] = file_path
                    else:
                        responses[question.id] = "Invalid file type"
                else:
                    responses[question.id] = "No file uploaded"
            elif question.question_type == 'slider':
                responses[question.id] = request.form.get(str(question.id), "N/A")
            elif question.question_type == 'date':
                responses[question.id] = request.form.get(str(question.id), "N/A")
            else:
                submitted_answer = request.form.get(str(question.id))
                if language != 'en' and submitted_answer:
                    try:
                        translated_answer = translate_ans(submitted_answer, source=language, dest='en')
                    except Exception:
                        translated_answer = submitted_answer
                else:
                    translated_answer = submitted_answer or "N/A"
                responses[question.id] = translated_answer

        new_response = Response(form_id=form.id, responses=json.dumps(responses))
        db.session.add(new_response)
        db.session.commit()

        user = User.query.get(form.user_id)
        if user and user.email_notifications:
            send_notification_email(
                user,
                subject="New Form Response",
                body=f"Your form '{form.name}' has received a new response. Log in to your dashboard to view it. Thank you!"
            )

        flash('Form submitted successfully!', 'success')
        return redirect(url_for('main.submit_form', public_token=form.public_token))

    form_title = translate_text(form.name, language)
    form_description = translate_text(form.description, language)

    translated_questions = []
    for question in form.questions:
        translated_question = {
            'id': question.id,
            'question_text': translate_text(question.question_text, language),
            'question_type': question.question_type,
            'options': ', '.join([
                translate_text(option.strip(), language) for option in question.options.split(',')
            ]) if question.options else None
        }
        translated_questions.append(translated_question)

    return render_template(
        'submit_form.html',
        form=form,
        form_title=form_title,
        form_description=form_description,
        questions=translated_questions,
        selected_language=language,
        languages=languages
    )

@bp.route('/form/<int:form_id>/responses', methods=['GET'])
@login_required
def view_responses(form_id):
    form = Form.query.get_or_404(form_id)
    if form.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    responses = Response.query.filter_by(form_id=form_id).all()

    print("Questions:", [q.question_text for q in form.questions])
    print("Responses:", responses)

    processed_responses = []
    for response in responses:
        response_data = json.loads(response.responses)
        response_data['submitted_on'] = response.submitted_on
        processed_responses.append(response_data)

    return render_template(
        'view_responses.html',
        form=form,
        responses=processed_responses
    )

@bp.route('/form/<int:form_id>/responses/download.<string:format>', methods=['GET'])
@login_required
def download_responses(form_id, format):
    form = Form.query.get_or_404(form_id)
    if form.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('main.dashboard'))

    responses = Response.query.filter_by(form_id=form_id).all()

    if not responses:
        flash('No responses available for this form.', 'info')
        return redirect(url_for('main.view_responses', form_id=form_id))

    responses_data = []
    for response in responses:
        responses_data.append(json.loads(response.responses))

    question_headers = [q.question_text for q in form.questions]

    if format == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['#'] + question_headers)
        for i, response_data in enumerate(responses_data, start=1):
            row = [i] + [response_data.get(str(q.id), 'N/A') for q in form.questions]
            writer.writerow(row)

        csv_content = output.getvalue()
        output.close()

        response = make_response(csv_content)
        response.headers["Content-Disposition"] = f"attachment; filename={form.name.replace(' ', '_')}_responses.csv"
        response.headers["Content-Type"] = "text/csv"
        return response

    elif format == 'xlsx':
        output = BytesIO()
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Responses"

        ws.append(['#'] + question_headers)

        for i, response_data in enumerate(responses_data, start=1):
            row = [i] + [response_data.get(str(q.id), 'N/A') for q in form.questions]
            ws.append(row)

        wb.save(output)
        output.seek(0)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f"{form.name.replace(' ', '_')}_responses.xlsx"
        )

    flash('Invalid format specified.', 'danger')
    return redirect(url_for('main.view_responses', form_id=form_id))

@bp.route('/uploads/<path:file_path>')
@login_required
def download_file(file_path):
    uploads_dir = current_app.config['UPLOAD_FOLDER']
    try:
        safe_path = os.path.join(uploads_dir, os.path.basename(file_path))
        if os.path.exists(safe_path):
            return send_file(safe_path, as_attachment=True)
        else:
            flash("File not found.", "danger")
            return redirect(url_for('main.dashboard'))
    except Exception as e:
        current_app.logger.error(f"Error serving file {file_path}: {e}")
        flash("An error occurred while downloading the file.", "danger")
        return redirect(url_for('main.dashboard'))

@bp.route('/form/<public_token>/qr')
def form_qr(public_token):
    form = Form.query.filter_by(public_token=public_token).first_or_404()
    form_url = url_for('main.submit_form', public_token=public_token, _external=True)
    qr_buffer = generate_qr_code(form_url)
    return send_file(qr_buffer, mimetype='image/png', download_name=f'{form.name}_qr.png')

@bp.route('/settings', methods=['GET'])
@login_required
def settings():
    return render_template('settings.html', title="Settings")

@bp.route('/update_email', methods=['POST'])
@login_required
def update_email():
    new_email = request.form.get('email')
    if new_email and new_email != current_user.email:
        if User.query.filter_by(email=new_email).first():
            flash('Email address already in use.', 'danger')
        else:
            current_user.email = new_email
            db.session.commit()
            flash('Your email address has been updated.', 'success')
    else:
        flash('Please enter a valid email.', 'danger')
    return redirect(url_for('main.settings'))

@bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect.', 'danger')
    elif new_password != confirm_password:
        flash('New password and confirmation do not match.', 'danger')
    else:
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated.', 'success')
    return redirect(url_for('main.settings'))

@bp.route('/update_notifications', methods=['POST'])
@login_required
def update_notifications():
    email_notifications = 'email_notifications' in request.form
    current_user.email_notifications = email_notifications
    db.session.commit()
    flash('Notification preferences updated.', 'success')
    return redirect(url_for('main.settings'))

@bp.route('/delete-account', methods=['POST'])
@login_required
def delete_account():
    Form.query.filter_by(user_id=current_user.id).delete()
    
    Response.query.filter(Response.form_id.in_(
        db.session.query(Form.id).filter_by(user_id=current_user.id)
    )).delete()
    
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Your account and all associated data have been successfully deleted.', 'success')
    return redirect(url_for('main.index'))

@bp.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        secret = pyotp.random_base32()
        current_user.two_factor_secret = secret
        current_user.two_factor_enabled = True
        db.session.commit()

        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name="FormLingo"
        )
        flash('2FA enabled successfully. Use the QR code below with a 2FA app.', 'success')
        return render_template('enable_2fa.html', otp_uri=otp_uri)

    return render_template('enable_2fa.html')

@bp.route('/verify-2fa', methods=['GET', 'POST'])
@login_required
def verify_2fa():
    if not current_user.two_factor_enabled:
        flash('2FA is not enabled on your account.', 'info')
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        totp = pyotp.TOTP(current_user.two_factor_secret)

        if totp.verify(otp):
            flash('2FA verification successful.', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_2fa.html')

@bp.route('/disable-2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if request.method == 'POST':
        current_user.two_factor_enabled = False
        current_user.two_factor_secret = None
        db.session.commit()
        flash('2FA has been disabled for your account.', 'info')
        return redirect(url_for('main.dashboard'))

    return render_template('disable_2fa.html', title="Disable 2FA")

@bp.route('/send-otp', methods=['POST'])
@login_required
def send_otp():
    totp = pyotp.TOTP(current_user.two_factor_secret)
    otp = totp.now()

    msg = Message(
        subject="Your OTP Code",
        recipients=[current_user.email],
        body=f"Your OTP code is: {otp}",
        sender="noreply@formlingo.com"
    )
    mail.send(msg)

    flash('OTP sent to your email.', 'info')
    return redirect(url_for('main.verify_2fa'))

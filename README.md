# FormLingo

FormLingo is a versatile form management application built with Flask, enabling users to create, manage, and submit forms efficiently. It supports features like multi-language form translation, file uploads, two-factor authentication (2FA), and response management with secure and user-friendly design.

## Features

* Create Forms: Create and manage forms with different question types, including multiple-choice, text, dropdown, file uploads, etc.
* Response Management: View and download form responses in CSV or XLSX formats.
* Multi-Language Support: Translate forms into multiple languages for global accessibility.
* Two-Factor Authentication (2FA): Secure your account with 2FA for added security.
* Email Notifications: Receive notifications for form responses via email.
* Search and Sort: Quickly find forms with search and sort functionality.
* Secure File Handling: Ensure safe and secure file uploads and downloads.
* Form Sharing: Share forms via links or QR codes for easy access.
* Customizable Settings: Configure preferences, including enabling/disabling 2FA and email notifications.

## Installation

### Prerequisites

1. Python 3.8 or later installed on your system.
2. Git installed.
3. A virtual environment tool (optional but recommended).

### Clone the Repository

```bash
git clone https://github.com/your-username/FormLingo.git
cd FormLingo
```

### Set Up the Environment
#### 1.	Create a virtual environment:
```bash
python -m venv venv
```

#### 2.	Activate the virtual environment:

On macOS/Linux:
```bash
source venv/bin/activate
```

On Windows:
```bash
venv\Scripts\activate
```

#### 3.	Install dependencies:
```bash
pip install -r requirements.txt
```

## Set Up Environment Variables

### Create a .env file in the root directory and configure the following:

```bash
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
SECURITY_PASSWORD_SALT=your-password-salt
SQLALCHEMY_DATABASE_URI=sqlite:///formlingo.db
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-email-password
MAIL_DEFAULT_SENDER=noreply@example.com
```

## Database Migration

### Run the following commands to set up the database:

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

### Run the Application

Start the Flask development server:
```bash
flask run
```

The app will be available at http://127.0.0.1:5000.

## Usage

### Create a Form
1.	Log in to your account.
2.	Navigate to the dashboard and click “New Form.”
3.	Add questions.

### Manage Responses
1.	Go to the “Responses” section for a form.
2.	View and download responses in CSV or XLSX formats.

### Account Settings
1.	Enable/disable 2FA for added security.
2.	Update email notification preferences.
3.	Change Password
4.	Change Email

## Technologies Used
* Backend: Flask, Flask-SQLAlchemy, Flask-WTF
* Frontend: HTML, CSS (Bootstrap), JavaScript
* Database: SQLite (default), configurable for PostgreSQL/MySQL
* Email: Flask-Mail
* Translation: Deep Translator
* Authentication: Flask-Login, Flask-WTF

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for review.

## License

This project is licensed under the Unlicense. See LICENSE for details.

## Contact

For any queries, reach out at palashlalwani.r@gmail.com.

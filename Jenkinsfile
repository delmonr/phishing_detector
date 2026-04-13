pipeline {
    agent any

    environment {
        VENV_DIR = 'venv'
    }

    stages {

        stage('Checkout') {
            steps {
                echo 'Cloning the project...'
                checkout scm
            }
        }

        stage('Setup Python Environment') {
            steps {
                echo 'Creating virtual environment...'
                bat 'python -m venv venv'
            }
        }

        stage('Install Dependencies') {
            steps {
                echo 'Upgrading pip...'
                bat 'venv\\Scripts\\python -m pip install --upgrade pip'
                echo 'Installing numpy...'
                bat 'venv\\Scripts\\pip install --only-binary=:all: numpy==2.4.4'
                echo 'Installing scikit-learn...'
                bat 'venv\\Scripts\\pip install --only-binary=:all: scikit-learn==1.3.2'
                echo 'Installing Flask packages...'
                bat 'venv\\Scripts\\pip install flask==3.0.3 flask-sqlalchemy==3.1.1 werkzeug==3.0.3'
            }
        }

        stage('Run Model Test') {
            steps {
                echo 'Testing the phishing detection model...'
                bat '''
                    venv\\Scripts\\python -c "
from model import PhishingDetector
d = PhishingDetector()
r1 = d.predict('https://google.com')
r2 = d.predict('http://192.168.1.1/login/paypal-verify?user=@abc')
print('Safe test:', r1['label'], r1['risk_percentage'])
print('Phish test:', r2['label'], r2['risk_percentage'])
assert r1['label'] == 'safe', 'FAILED: google.com should be safe'
assert r2['label'] == 'phishing', 'FAILED: phishing URL not detected'
print('All tests passed!')
"
                '''
            }
        }

        stage('Run Flask App Check') {
            steps {
                echo 'Checking Flask app starts correctly...'
                bat '''
                    venv\\Scripts\\python -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('Flask app and database initialized successfully!')
"
                '''
            }
        }

        stage('Build Success') {
            steps {
                echo '========================================='
                echo ' PhishGuard AI Pipeline PASSED!'
                echo '========================================='
            }
        }
    }

    post {
        success {
            echo 'BUILD SUCCESSFUL - PhishGuard AI is ready to deploy!'
        }
        failure {
            echo 'BUILD FAILED - Check the logs above for errors.'
        }
    }
}
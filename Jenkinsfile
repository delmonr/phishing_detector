pipeline {
    agent any

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
                bat 'venv\\Scripts\\pip install --only-binary=:all: scikit-learn==1.7.2'
                echo 'Installing Flask packages...'
                bat 'venv\\Scripts\\pip install flask==3.0.3 flask-sqlalchemy==3.1.1 werkzeug==3.0.3'
            }
        }

        stage('Run Model Test') {
            steps {
                echo 'Testing the phishing detection model...'
                bat 'venv\\Scripts\\python -c "from model import PhishingDetector; d = PhishingDetector(); r1 = d.predict(chr(104)+chr(116)+chr(116)+chr(112)+chr(115)+chr(58)+chr(47)+chr(47)+chr(103)+chr(111)+chr(111)+chr(103)+chr(108)+chr(101)+chr(46)+chr(99)+chr(111)+chr(109)); print(r1[chr(108)+chr(97)+chr(98)+chr(101)+chr(108)]); print(chr(84)+chr(101)+chr(115)+chr(116)+chr(32)+chr(80)+chr(97)+chr(115)+chr(115)+chr(101)+chr(100))"'
            }
        }

        stage('Run Flask App Check') {
            steps {
                echo 'Checking Flask app initializes correctly...'
                bat 'venv\\Scripts\\python -c "from app import app, db; app.app_context().push(); db.create_all(); print(chr(70)+chr(108)+chr(97)+chr(115)+chr(107)+chr(32)+chr(79)+chr(75))"'
            }
        }

        stage('Build Success') {
            steps {
                echo 'PhishGuard AI Pipeline PASSED!'
            }
        }
    }

    post {
        success {
            echo 'BUILD SUCCESSFUL - PhishGuard AI is ready!'
        }
        failure {
            echo 'BUILD FAILED - Check the logs above for errors.'
        }
    }
}
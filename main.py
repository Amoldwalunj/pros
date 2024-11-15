import logging
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from dotenv import load_dotenv
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_cors import cross_origin
from models import db, Recording, AssignedWorker, User, UserRole
from datetime import datetime, timedelta
import requests
import boto3
import time
import re
import os
import uuid
import json



load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


app = Flask(__name__)

# Database credentials
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

# Construct the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Configure CORS for Flask - allow all origins for troubleshooting
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
# Configure SocketIO with CORS - allow all origins for troubleshooting
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


# Register your SQLAlchemy instance with your Flask app
db.init_app(app)
with app.app_context():
    db.create_all() 

 
# AWS credentials
REGION_NAME = os.getenv('REGION_NAME')
ACCESS_KEY = os.getenv('ACCESS_KEY')
SECRET_KEY = os.getenv('SECRET_KEY')
BUCKET_NAME = os.getenv('BUCKET_NAME')
OUTPUT_BUCKET_NAME = os.getenv('OUTPUT_BUCKET_NAME')
ROLE_ARN = os.getenv('ROLE_ARN')


s3_client = boto3.client('s3', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name=REGION_NAME)
transcribe_client = boto3.client('transcribe', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name=REGION_NAME)



def transform_name(name):
    # Replace spaces and non-compliant characters with underscores
    return re.sub(r'[^0-9a-zA-Z._-]', '_', name)


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    logger.info("Received login request.")
    
    # Parse JSON data from the request
    if not request.json:
        logger.error("No JSON data provided in the request.")
        return jsonify({'error': 'Please provide login details in JSON format.'}), 400
    
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Check if email and password are provided
    if not email or not password:
        logger.error("Email or password is missing.")
        return jsonify({'error': 'Email and password are required.'}), 400

    try:
        # Check if user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            logger.error(f"No user found with email: {email}")
            return jsonify({'error': 'Invalid email or password.'}), 401
        
        # Verify password (replace with actual hashed password verification in production)
        if user.password != password:  # Replace with a secure password verification
            logger.error("Password verification failed.")
            return jsonify({'error': 'Invalid email or password.'}), 401

        logger.info(f"User {user.email} logged in successfully.")
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user.user_id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role.value
            }
        }), 200
    except Exception as e:
        logger.error(f"An error occurred during login: {e}")
        return jsonify({'error': 'An error occurred. Please try again later.'}), 500
    

@app.route('/workers', methods=['GET'])
@cross_origin()
def get_all_workers():
    logger.info("Received request to fetch all workers.")
    try:
        # Query all users with role 'worker'
        workers = User.query.filter_by(role=UserRole.WORKER).all()
        if not workers:
            logger.info("No workers found.")
            return jsonify({'message': 'No workers found.'}), 404
        # Format the worker data into JSON-serializable format
        worker_list = [
            {
                'user_id': worker.user_id,
                'first_name': worker.first_name,
                'last_name': worker.last_name,
                'email': worker.email,
                'role': worker.role.value
            }
            for worker in workers
        ]
        logger.info(f"Fetched {len(worker_list)} workers.")
        return jsonify({'workers': worker_list}), 200
    except Exception as e:
        logger.error(f"An error occurred while fetching workers: {e}")
        return jsonify({'error': 'An error occurred. Please try again later.'}), 500


@app.route('/upload_healthscribe', methods=['POST'])
@cross_origin()
def upload_file():
    logger.info("Received request to upload file.")
    if 'file' not in request.files:
        logger.error("No file part in the request.")
        return jsonify({'error': 'Please Updload the file.'}), 400
    file = request.files['file']
    if file.filename == '':
        logger.error("No file selected for upload.")
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        transformed_filename = transform_name(unique_filename)
        s3_path = f'avahi-recorded-audio-demo/{transformed_filename}'

        try:
            # Upload file to S3
            s3_client.upload_fileobj(file, BUCKET_NAME, s3_path)
            logger.info(f"File uploaded to S3 with path: {s3_path}")
        except Exception as e:
            logger.error(f"Failed to upload file to S3: {e}")
            return jsonify({'error': 'File upload failed'}), 500
        
        # Check if a recording with the same transformed filename exists
        recording = Recording.query.filter_by(transformed_file_name=transformed_filename).first()
        if recording:
            # Update existing record
            recording.s3_path = s3_path
            recording.updated_at = datetime.utcnow()
            action = 'updated'
            logger.info(f"Existing recording with filename {transformed_filename} updated.")
        else:
            # Create a new record
            recording = Recording(
                s3_path=s3_path,
                transformed_file_name=transformed_filename,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.session.add(recording)
            action = 'created'
            logger.info(f"New recording with filename {transformed_filename} created.")
        # Commit changes to the database
        try:
            db.session.commit()
            logger.info(f"Recording {action} successfully in the database.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to commit recording to the database: {e}")
            return jsonify({'error': 'Database error'}), 500
        
        return jsonify({
            'response': f'Recording {action} successfully',
            'transformed_filename': transformed_filename,
            's3_path': s3_path
        })


@app.route('/transcribe', methods=['POST'])
@cross_origin()
def transcribe_file():
    # Expecting transformed_filename and s3_path to be provided in the request JSON
    data = request.get_json()
    transformed_filename = data.get('transformed_filename')
    s3_path = data.get('s3_path')
    if not transformed_filename or not s3_path:
        return jsonify({'error': 'Required data missing. Please provide both transformed_filename and s3_path.'}), 400
    job_name = f"avahi-{transformed_filename[:-4]}"
    s3_input_uri = f"s3://{BUCKET_NAME}/{s3_path}"
    # Start the transcription job
    response = transcribe_client.start_medical_scribe_job(
        MedicalScribeJobName=job_name,
        Media={'MediaFileUri': s3_input_uri},
        OutputBucketName=OUTPUT_BUCKET_NAME,
        DataAccessRoleArn=ROLE_ARN,
        Settings={
            'ShowSpeakerLabels': True,
            'MaxSpeakerLabels': 29,
            'ChannelIdentification': False
        }
    )
    # Polling the job status until it completes or fails
    while True:
        status = transcribe_client.get_medical_scribe_job(MedicalScribeJobName=job_name)
        if status['MedicalScribeJob']['MedicalScribeJobStatus'] in ['COMPLETED', 'FAILED']:
            break
        time.sleep(5)
    
    if status['MedicalScribeJob']['MedicalScribeJobStatus'] == 'FAILED':
        return jsonify({'error': 'Transcription job failed'}), 500
    transcript_uri = status['MedicalScribeJob']['MedicalScribeOutput']['TranscriptFileUri']
    summary_uri = status['MedicalScribeJob']['MedicalScribeOutput']['ClinicalDocumentUri']
    # Check if a recording with the same transformed filename exists in the database
    recording = Recording.query.filter_by(transformed_file_name=transformed_filename).first()
    if recording:
        # Update existing record
        recording.s3_path = s3_path
        recording.updated_at = datetime.utcnow()
        recording.job_name = job_name
        action = 'updated'
    # Commit changes to the database
    try:
        db.session.commit()
        logging.info(f"Recording {action} successfully in the database.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to commit recording to the database: {e}")
        return jsonify({'error': 'Database error'}), 500

    return jsonify({
        'TranscriptionFileUri': transcript_uri,
        'SummaryFileUri': summary_uri,
        'TransformedFilename': transformed_filename,
        'JobName': job_name
    })


@app.route('/fetch_healthscribe_report', methods=['POST'])
@cross_origin()
def fetch_healthscribe_report():
    # Fetch parameters from the request
    data = request.get_json()
    job_name = data.get('job_name')
    
    if not job_name:
        return jsonify({'error': 'Job name is required.'}), 400

    # External API configuration
    url = "https://wz2vc2s0xa.execute-api.us-east-1.amazonaws.com/fetch-healthscribe-outputs-for-recorded-audio/fetch-healthscribe-outputs-for-recorded-audio"
    headers = {
        'x-api-key': 'Tq6isgVNGT1v2yYpayLwA7Nuw2dmUmjXaR2UQ7jn',
        'Content-Type': 'application/json'
    }
    
    types = ["report", "icd10", "transcript"]
    results = {}

    # Loop over each type to get results
    for report_type in types:
        payload = json.dumps({
            "queryStringParameters": {
                "job_name": job_name,
                "type": report_type
            }
        })
        
        # Call the external API
        response = requests.post(url, headers=headers, data=payload)
        
        # Check if the response is successful
        print("response.status_code ======", response.status_code)
        if response.status_code == 200:
            data = json.loads(response.json().get('body', '[]'))
            
            # Process "report" type for formatting
            if report_type == "report":
                formatted_response = []
                for line in data:
                    line = line.strip()
                    if line.startswith("Section:"):
                        formatted_response.append(f"\n{line}")
                    elif line:  # Only add bullets to non-empty lines
                        formatted_response.append(f"  • {line}")
                results[report_type] = "\n".join(formatted_response)
            else:
                # For other types, add data directly
                results[report_type] = data
        else:
            results[report_type] = f"Error: Failed to fetch data for {report_type}"

    # Check if a recording with the job name exists in the database
    recording = Recording.query.filter_by(job_name=job_name).first()

    if recording:
        # Update existing record
        recording.visit_notes = results.get("report", "No report available")
        recording.icd_codes = json.dumps(results.get("icd10", []))
        recording.transcription = json.dumps(results.get("transcript", []))
        recording.updated_at = datetime.utcnow()
        action = 'updated'
    else:
        # Create a new record
        recording = Recording(
            transformed_file_name=job_name,
            visit_notes=results.get("report", "No report available"),
            icd_codes=json.dumps(results.get("icd10", [])),
            transcription=json.dumps(results.get("transcript", [])),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(recording)
        action = 'created'

    # Commit changes to the database
    try:
        db.session.commit()
        logging.info(f"Recording {action} successfully in the database.")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to commit recording to the database: {e}")
        return jsonify({'error': 'Database error'}), 500

    # Return all types in a single JSON response
    return jsonify({"status": "success", "data": results})


@app.route('/recordings', methods=['GET'])
def get_recordings():
    # Get filter parameters from query string
    date = request.args.get('date')  # Expected values: 'month', 'seven_days', 'today'
    validated = request.args.get('validated')  # Expected as 'true' or 'false'
    assigned_worker = request.args.get('assigned_worker')  # Expected as worker name or ID
    # Initialize the base query
    query = Recording.query
    # Apply 'updated_at' filter based on keyword
    if date:
        now = datetime.utcnow()
        if date == 'month':
            start_date = now - timedelta(days=30)
        elif date == 'seven_days':
            start_date = now - timedelta(days=7)
        elif date == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return jsonify({'error': 'Invalid value for updated_at. Use month, seven_days, or today.'}), 400
        
        query = query.filter(
            Recording.updated_at >= start_date,
            Recording.updated_at <= now
        )

    # Apply 'validated' filter if provided
    if validated:
        if validated.lower() == 'true':
            query = query.filter(Recording.validated == True)
        elif validated.lower() == 'false':
            query = query.filter(Recording.validated == False)
        else:
            return jsonify({'error': 'Invalid value for validated. Use true or false.'}), 400
        
    # Apply 'assigned_worker' filter if provided (by name or ID)
    if assigned_worker:
        # Check if assigned_worker is an ID (if it's numeric, assume it's an ID)
        if assigned_worker.isdigit():
            # Filter by assigned_worker ID
            worker_id = int(assigned_worker)
            query = query.filter(Recording.assigned_to == worker_id)
        else:
            # Filter by worker's name (first_name and last_name)
            query = query.join(AssignedWorker).join(User).filter(
                (User.first_name + ' ' + User.last_name).ilike(f"%{assigned_worker}%")
            )

    # Execute the query and fetch results
    recordings = query.all()
    # Convert results to JSON-serializable format
    results = [
        {
            'recording_id': recording.recording_id,
            's3_path': recording.s3_path,
            'transformed_file_name': recording.transformed_file_name,
            'transcription': recording.transcription,
            'visit_notes': recording.visit_notes,
            'icd_codes': recording.icd_codes,
            'status': recording.status,
            'assigned_to': recording.assigned_to,
            'validated': recording.validated,
            'created_at': recording.created_at.isoformat(),
            'updated_at': recording.updated_at.isoformat()
        }
        for recording in recordings
    ]
    return jsonify({'status': 'success', 'data': results})


@app.route('/generate_presigned_url/<int:recording_id>', methods=['GET'])
def generate_presigned_url(recording_id):
    # Fetch the recording from the database
    recording = Recording.query.get(recording_id)
    
    if not recording:
        return jsonify({'message': 'Recording not found'}), 404

    # Get the S3 path from the recording
    s3_path = recording.s3_path

    try:
        # Generate a presigned URL for the S3 object
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': BUCKET_NAME,   # Replace with your S3 bucket name
                'Key': s3_path
            },
            ExpiresIn=3600  # Expiration time in seconds
        )
        return jsonify({
            'message': 'Presigned URL generated successfully',
            'presigned_url': presigned_url
        }), 200
    except Exception as e:
        return jsonify({'message': f'Error generating presigned URL: {str(e)}'}), 500
    

@app.route('/recordings/count', methods=['GET'])
def get_recording_counts():
    # Get filters from the query string (optional)
    date = request.args.get('date')  # Optionally filter by date, e.g., 'month', 'seven_days', 'today'
    # Initialize the base query for Recording
    query = Recording.query
    # Apply date filter if provided
    if date:
        now = datetime.utcnow()
        if date == 'month':
            start_date = now - timedelta(days=30)
        elif date == 'seven_days':
            start_date = now - timedelta(days=7)
        elif date == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            return jsonify({'error': 'Invalid value for date filter. Use month, seven_days, or today.'}), 400
        query = query.filter(Recording.updated_at >= start_date)
    # Count total number of recordings
    total_recordings = query.count()
    # Count of recordings assigned to a worker
    assigned_recordings = query.filter(Recording.assigned_to.isnot(None)).count()
    # Count of unassigned recordings
    unassigned_recordings = query.filter(Recording.assigned_to.is_(None)).count()
    # Count of validated recordings
    validated_recordings = query.filter(Recording.validated == True).count()
    # Return the counts in a JSON response
    return jsonify({
        'status': 'success',
        'data': {
            'total_recordings': total_recordings,
            'assigned_recordings': assigned_recordings,
            'unassigned_recordings': unassigned_recordings,
            'validated_recordings': validated_recordings
        }
    })



if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8004)
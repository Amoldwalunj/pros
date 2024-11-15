from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum

db = SQLAlchemy()

# Enum for user roles
class UserRole(Enum):
    DOCTOR = "doctor"
    WORKER = "worker"

# Updated AssignedWorker Model
class AssignedWorker(db.Model):
    __tablename__ = 'assigned_workers'
    
    assigned_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    max_assignments = db.Column(db.Integer, default=5)
    current_assignments = db.Column(db.Integer, default=0)
    
    # Relationship to the User model (one-to-one relationship)
    worker_user = db.relationship("User", backref="assigned_worker", foreign_keys=[user_id])
    
    # Relationship to Recording model
    recordings = db.relationship("Recording", back_populates="assigned_worker", lazy="dynamic")
    
    def __repr__(self):
        return f"<AssignedWorker {self.assigned_id}, Max Assignments: {self.max_assignments}, Current Assignments: {self.current_assignments}>"

# Updated Recording Model
class Recording(db.Model):
    __tablename__ = 'recordings'
    
    recording_id = db.Column(db.Integer, primary_key=True)
    s3_path = db.Column(db.String(255), nullable=False, unique=True)
    transformed_file_name = db.Column(db.String(255))
    transcription = db.Column(db.Text)
    visit_notes = db.Column(db.Text)
    icd_codes = db.Column(db.Text)  # Consider using a separate table if ICD codes are multiple and need normalization
    status = db.Column(db.String(50), default='unassigned', index=True)
    
    # Foreign key to AssignedWorker model
    assigned_to = db.Column(db.Integer, db.ForeignKey('assigned_workers.assigned_id'), nullable=True)
    validated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    job_name = db.Column(db.String(255), nullable=True)
    
    # Relationships to AssignedWorker
    assigned_worker = db.relationship(
        "AssignedWorker", 
        back_populates="recordings",
        foreign_keys=[assigned_to],
        primaryjoin="Recording.assigned_to == AssignedWorker.assigned_id"
    )
    
    def __repr__(self):
        return f"<Recording {self.recording_id}, S3 Path: {self.s3_path}, Status: {self.status}>"

# Updated User Model
class User(db.Model):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    role = db.Column(db.Enum(UserRole), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store hashed passwords
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<User {self.first_name} {self.last_name}, Role: {self.role.value}>"

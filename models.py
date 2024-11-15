from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Recording(db.Model):
    __tablename__ = 'recordings'
    
    recording_id = db.Column(db.Integer, primary_key=True)
    s3_path = db.Column(db.String(255), nullable=False, unique=True)
    transformed_file_name = db.Column(db.String(255))
    transcription = db.Column(db.Text)
    visit_notes = db.Column(db.Text)
    icd_codes = db.Column(db.Text)  # Consider using a separate table if ICD codes are multiple and need normalization
    status = db.Column(db.String(50), default='unassigned', index=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey('workers.worker_id'), nullable=True)
    validated = db.Column(db.Boolean, default=False)  # Changed to Boolean for clearer validation state
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    job_name = db.Column(db.String(255), nullable=True)
    # Relationships
    assigned_worker = db.relationship("Worker", back_populates="recordings")


class Worker(db.Model):
    __tablename__ = 'workers'
    
    worker_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    max_assignments = db.Column(db.Integer, default=5)
    current_assignments = db.Column(db.Integer, default=0)    
    # Relationships
    recordings = db.relationship("Recording", back_populates="assigned_worker", lazy="dynamic")
    
    def has_capacity(self):
        """Check if worker can take on more assignments."""
        return self.current_assignments < self.max_assignments

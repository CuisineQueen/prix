#!/usr/bin/env python3
"""
Prix AI Security Dashboard
Web-based monitoring and control interface
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import threading
import time
from datetime import datetime
from main import PrixSecuritySystem, DatabaseManager
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'prix_security_dashboard_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global security system instance
prix_system = None
database = None

def init_dashboard():
    """Initialize dashboard with security system"""
    global prix_system, database
    database = DatabaseManager()
    prix_system = PrixSecuritySystem()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get system status"""
    if prix_system:
        return jsonify(prix_system.get_status())
    return jsonify({'status': 'stopped', 'recent_threats': 0, 'threats': []})

@app.route('/api/threats')
def get_threats():
    """Get all threats"""
    if database:
        threats = database.get_recent_threats(limit=100)
        return jsonify({
            'threats': [
                {
                    'id': t.id,
                    'type': t.type,
                    'severity': t.severity,
                    'description': t.description,
                    'source': t.source,
                    'timestamp': t.timestamp.isoformat(),
                    'file_path': t.file_path,
                    'process_id': t.process_id,
                    'network_connection': t.network_connection,
                    'eliminated': t.eliminated
                }
                for t in threats
            ]
        })
    return jsonify({'threats': []})

@app.route('/api/start', methods=['POST'])
def start_system():
    """Start security system"""
    if prix_system and not prix_system.running:
        prix_system.start()
        return jsonify({'success': True, 'message': 'Security system started'})
    return jsonify({'success': False, 'message': 'System already running or not initialized'})

@app.route('/api/stop', methods=['POST'])
def stop_system():
    """Stop security system"""
    if prix_system and prix_system.running:
        prix_system.stop()
        return jsonify({'success': True, 'message': 'Security system stopped'})
    return jsonify({'success': False, 'message': 'System not running or not initialized'})

@app.route('/api/eliminate/<threat_id>', methods=['POST'])
def eliminate_threat(threat_id):
    """Manually eliminate a threat"""
    if prix_system:
        # Get threat from database
        conn = sqlite3.connect('prix_security.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM threats WHERE id = ?', (threat_id,))
        threat_data = cursor.fetchone()
        conn.close()
        
        if threat_data:
            from main import Threat
            threat = Threat(
                id=threat_data[0],
                type=threat_data[1],
                severity=threat_data[2],
                description=threat_data[3],
                source=threat_data[4],
                timestamp=datetime.fromisoformat(threat_data[5]),
                file_path=threat_data[6],
                process_id=threat_data[7],
                network_connection=json.loads(threat_data[8]) if threat_data[8] else None,
                eliminated=bool(threat_data[9])
            )
            
            success = prix_system.eliminator.eliminate_threat(threat)
            return jsonify({'success': success, 'message': f'Threat {threat_id} {"eliminated" if success else "failed to eliminate"}'})
    
    return jsonify({'success': False, 'message': 'Threat not found'})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', prix_system.get_status() if prix_system else {'status': 'stopped'})

def broadcast_updates():
    """Broadcast real-time updates to connected clients"""
    while True:
        if prix_system and prix_system.running:
            status = prix_system.get_status()
            socketio.emit('status', status)
        time.sleep(5)

if __name__ == '__main__':
    init_dashboard()
    
    # Start background thread for broadcasting updates
    update_thread = threading.Thread(target=broadcast_updates, daemon=True)
    update_thread.start()
    
    # Run the dashboard
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

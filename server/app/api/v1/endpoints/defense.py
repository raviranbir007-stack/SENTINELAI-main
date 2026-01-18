"""
Defense API Endpoints
Handles defense events, quarantine management, and blocking operations
"""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime
import logging

from .auth import get_current_user
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()


class DefenseEvent(BaseModel):
    client_id: str
    event: str
    attack_id: Optional[str] = None
    attack: Optional[Dict] = None
    alert_number: Optional[int] = None
    max_alerts: Optional[int] = None
    user_initiated: Optional[bool] = None
    timestamp: str


class QuarantineRequest(BaseModel):
    client_id: str
    reason: str
    admin_password: Optional[str] = None


class BlockRequest(BaseModel):
    client_id: str
    target_type: str  # 'ip', 'domain', 'file', 'app'
    target: str
    reason: str


@router.post("/event")
async def receive_defense_event(
    event: DefenseEvent,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    Receive and log defense events from clients
    """
    try:
        logger.info(f"Defense event received from {event.client_id}: {event.event}")
        
        # Store event in database
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO defense_events 
            (client_id, event_type, event_data, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (
            event.client_id,
            event.event,
            str(event.dict()),
            event.timestamp
        ))
        db.commit()
        
        # Handle specific events
        if event.event == 'ATTACK_ALERT':
            logger.warning(f"Attack alert #{event.alert_number}/{event.max_alerts} from {event.client_id}")
            
            # Notify administrators if critical
            if event.alert_number >= event.max_alerts - 1:
                logger.critical(f"Client {event.client_id} approaching auto-quarantine!")
        
        elif event.event == 'SYSTEM_QUARANTINED':
            logger.critical(f"SYSTEM QUARANTINED: {event.client_id}")
            
            # Mark client as quarantined
            cursor.execute('''
                UPDATE clients
                SET status = 'quarantined', quarantine_time = ?
                WHERE client_id = ?
            ''', (datetime.now(), event.client_id))
            db.commit()
        
        elif event.event == 'QUARANTINE_LIFTED':
            logger.info(f"Quarantine lifted for {event.client_id}")
            
            cursor.execute('''
                UPDATE clients
                SET status = 'active', quarantine_time = NULL
                WHERE client_id = ?
            ''', (event.client_id,))
            db.commit()
        
        return {
            'status': 'success',
            'message': 'Defense event logged',
            'event_id': cursor.lastrowid
        }
        
    except Exception as e:
        logger.error(f"Failed to process defense event: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/quarantine")
async def initiate_quarantine(
    request: QuarantineRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    Initiate or lift quarantine for a client
    """
    try:
        logger.info(f"Quarantine request for {request.client_id}")
        
        # Verify admin privileges if lifting quarantine
        if request.admin_password:
            # In production, verify admin password properly
            # For now, just log
            logger.info(f"Quarantine lift requested with admin credentials")
        
        # Record quarantine action
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO quarantine_actions
            (client_id, action, reason, admin_user, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            request.client_id,
            'INITIATE' if not request.admin_password else 'LIFT',
            request.reason,
            current_user['username'],
            datetime.now()
        ))
        db.commit()
        
        return {
            'status': 'success',
            'message': 'Quarantine action processed',
            'action_id': cursor.lastrowid
        }
        
    except Exception as e:
        logger.error(f"Failed to process quarantine request: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/block")
async def add_block(
    request: BlockRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    Record a blocking action
    """
    try:
        logger.info(f"Block request from {request.client_id}: {request.target_type} - {request.target}")
        
        # Store block action
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO blocked_entities
            (client_id, target_type, target, reason, blocked_by, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            request.client_id,
            request.target_type,
            request.target,
            request.reason,
            current_user['username'],
            datetime.now()
        ))
        db.commit()
        
        return {
            'status': 'success',
            'message': 'Block recorded',
            'block_id': cursor.lastrowid
        }
        
    except Exception as e:
        logger.error(f"Failed to record block: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/status/{client_id}")
async def get_defense_status(
    client_id: str,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    Get defense status for a client
    """
    try:
        cursor = db.cursor()
        
        # Get recent defense events
        cursor.execute('''
            SELECT event_type, event_data, timestamp
            FROM defense_events
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
        ''', (client_id,))
        
        events = []
        for row in cursor.fetchall():
            events.append({
                'event_type': row[0],
                'event_data': row[1],
                'timestamp': row[2]
            })
        
        # Get blocked entities
        cursor.execute('''
            SELECT target_type, target, reason, timestamp
            FROM blocked_entities
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (client_id,))
        
        blocked = []
        for row in cursor.fetchall():
            blocked.append({
                'target_type': row[0],
                'target': row[1],
                'reason': row[2],
                'timestamp': row[3]
            })
        
        # Get quarantine status
        cursor.execute('''
            SELECT status, quarantine_time
            FROM clients
            WHERE client_id = ?
        ''', (client_id,))
        
        client_row = cursor.fetchone()
        is_quarantined = client_row[0] == 'quarantined' if client_row else False
        quarantine_time = client_row[1] if client_row else None
        
        return {
            'client_id': client_id,
            'is_quarantined': is_quarantined,
            'quarantine_time': quarantine_time,
            'recent_events': events,
            'blocked_entities': blocked
        }
        
    except Exception as e:
        logger.error(f"Failed to get defense status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/statistics")
async def get_defense_statistics(
    current_user: dict = Depends(get_current_user),
    db=Depends(get_db)
):
    """
    Get overall defense statistics
    """
    try:
        cursor = db.cursor()
        
        # Count attacks detected
        cursor.execute('''
            SELECT COUNT(*)
            FROM defense_events
            WHERE event_type = 'ATTACK_ALERT'
        ''')
        attacks_detected = cursor.fetchone()[0]
        
        # Count quarantined systems
        cursor.execute('''
            SELECT COUNT(*)
            FROM clients
            WHERE status = 'quarantined'
        ''')
        quarantined_systems = cursor.fetchone()[0]
        
        # Count blocked entities
        cursor.execute('''
            SELECT target_type, COUNT(*)
            FROM blocked_entities
            GROUP BY target_type
        ''')
        blocked_by_type = dict(cursor.fetchall())
        
        # Recent attack types
        cursor.execute('''
            SELECT event_data, COUNT(*)
            FROM defense_events
            WHERE event_type = 'ATTACK_ALERT'
            AND timestamp > datetime('now', '-7 days')
            GROUP BY event_data
            ORDER BY COUNT(*) DESC
            LIMIT 10
        ''')
        
        return {
            'attacks_detected': attacks_detected,
            'quarantined_systems': quarantined_systems,
            'blocked_entities': blocked_by_type,
            'total_blocked': sum(blocked_by_type.values())
        }
        
    except Exception as e:
        logger.error(f"Failed to get defense statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

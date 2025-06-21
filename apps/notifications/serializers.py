"""
Serializers for notifications app
"""
from rest_framework import serializers
from .models import Notification


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model"""
    
    class Meta:
        model = Notification
        fields = [
            'id', 'title', 'message', 'type', 'is_read', 
            'action_url', 'metadata', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']
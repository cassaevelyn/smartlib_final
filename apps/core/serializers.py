"""
Core serializers for common functionality
"""
from rest_framework import serializers
from .models import ActivityLog, SystemConfiguration, FileUpload


class ActivityLogSerializer(serializers.ModelSerializer):
    """Serializer for ActivityLog model"""
    activity_type_display = serializers.CharField(source='get_activity_type_display', read_only=True)
    user_display = serializers.CharField(source='user.get_full_name', read_only=True)
    
    class Meta:
        model = ActivityLog
        fields = [
            'id', 'user', 'user_display', 'activity_type', 
            'activity_type_display', 'description', 'ip_address',
            'created_at', 'metadata'
        ]
        read_only_fields = ['id', 'created_at']


class SystemConfigurationSerializer(serializers.ModelSerializer):
    """Serializer for SystemConfiguration model"""
    
    class Meta:
        model = SystemConfiguration
        fields = ['id', 'key', 'value', 'description', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class FileUploadSerializer(serializers.ModelSerializer):
    """Serializer for FileUpload model"""
    file_size_mb = serializers.ReadOnlyField()
    uploaded_by_display = serializers.CharField(source='uploaded_by.get_full_name', read_only=True)
    
    class Meta:
        model = FileUpload
        fields = [
            'id', 'file', 'original_name', 'file_type', 'file_size',
            'file_size_mb', 'mime_type', 'uploaded_by', 'uploaded_by_display',
            'created_at'
        ]
        read_only_fields = ['id', 'file_size', 'mime_type', 'created_at']
    
    def create(self, validated_data):
        validated_data['uploaded_by'] = self.context['request'].user
        validated_data['file_size'] = validated_data['file'].size
        validated_data['mime_type'] = validated_data['file'].content_type
        return super().create(validated_data)


class BaseModelSerializer(serializers.ModelSerializer):
    """
    Base serializer that includes common fields for models extending BaseModel
    """
    created_by_display = serializers.CharField(source='created_by.get_full_name', read_only=True)
    updated_by_display = serializers.CharField(source='updated_by.get_full_name', read_only=True)
    
    class Meta:
        abstract = True
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'created_by', 'updated_by',
            'is_deleted', 'deleted_at'
        ]
    
    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        validated_data['updated_by'] = self.context['request'].user
        return super().update(instance, validated_data)
"""Serializers for the vehicles app."""

from rest_framework import serializers
from .models import Vehicle, VehicleImage


class VehicleImageSerializer(serializers.ModelSerializer):
    """Serializer for vehicle images."""
    
    image_url = serializers.CharField(source="image.url", read_only=True)
    
    class Meta:
        model = VehicleImage
        fields = ["id", "image", "image_url", "alt_text", "is_main"]
        read_only_fields = ["id"]


class VehicleSerializer(serializers.ModelSerializer):
    """Serializer for vehicles."""
    
    images = VehicleImageSerializer(many=True, read_only=True)
    main_image = serializers.SerializerMethodField()
    
    class Meta:
        model = Vehicle
        fields = [
            "id", "make", "model", "year", "price_per_day",
            "description", "is_published", "images", "main_image",
            "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]
    
    def get_main_image(self, obj):
        """Get the main image URL."""
        main_image = obj.images.filter(is_main=True).first()
        if main_image:
            return {
                "id": main_image.id,
                "url": main_image.image.url,
                "alt_text": main_image.alt_text
            }
        return None


class VehicleCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating vehicles."""
    
    class Meta:
        model = Vehicle
        fields = [
            "make", "model", "year", "price_per_day",
            "description", "is_published"
        ]


class VehicleUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating vehicles."""
    
    class Meta:
        model = Vehicle
        fields = [
            "make", "model", "year", "price_per_day",
            "description", "is_published"
        ]


class ImageUploadSerializer(serializers.ModelSerializer):
    """Serializer for uploading vehicle images."""
    
    class Meta:
        model = VehicleImage
        fields = ["image", "alt_text", "is_main"]
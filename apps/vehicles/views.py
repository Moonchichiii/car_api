"""Views for the vehicles app."""

from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.db import transaction

from .models import Vehicle, VehicleImage
from .serializers import (
    VehicleSerializer, VehicleCreateSerializer, VehicleUpdateSerializer,
    ImageUploadSerializer
)


class VehicleViewSet(viewsets.ModelViewSet):
    """ViewSet for vehicle operations."""
    
    queryset = Vehicle.objects.all().prefetch_related("images")
    
    def get_serializer_class(self):
        if self.action == "create":
            return VehicleCreateSerializer
        elif self.action in ["update", "partial_update"]:
            return VehicleUpdateSerializer
        return VehicleSerializer
    
    def get_permissions(self):
        """Admin only for create, update, destroy operations."""
        if self.action in ["create", "update", "partial_update", "destroy"]:
            return [IsAdminUser()]
        return []
    
    def get_queryset(self):
        """Filter to published vehicles for non-admin users."""
        queryset = super().get_queryset()
        if not self.request.user.is_staff:
            queryset = queryset.filter(is_published=True)
        return queryset
    
    @action(detail=True, methods=["post"], permission_classes=[IsAdminUser])
    @transaction.atomic
    def upload_image(self, request, pk=None):
        """Upload image(s) for a vehicle."""
        vehicle = self.get_object()
        serializers = []
        
        # Handle multiple image uploads
        for key, file in request.FILES.items():
            if key.startswith("image"):
                data = {
                    "image": file,
                    "alt_text": request.data.get(f"alt_text_{key}", ""),
                    "is_main": request.data.get(f"is_main_{key}", False)
                }
                serializer = ImageUploadSerializer(data=data)
                
                if serializer.is_valid():
                    serializer.save(vehicle=vehicle)
                    serializers.append(serializer)
                else:
                    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        if serializers:
            return Response(
                [s.data for s in serializers],
                status=status.HTTP_201_CREATED
            )
        
        return Response(
            {"detail": "No valid images uploaded"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    @action(detail=True, methods=["patch"], permission_classes=[IsAdminUser])
    def set_main_image(self, request, pk=None):
        """Set a specific image as the main image."""
        vehicle = self.get_object()
        image_id = request.data.get("image_id")
        
        if not image_id:
            return Response(
                {"detail": "image_id is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            image = vehicle.images.get(id=image_id)
            
            # Update all images to not be main
            vehicle.images.update(is_main=False)
            
            # Set this image as main
            image.is_main = True
            image.save()
            
            return Response({"detail": "Main image updated"})
            
        except VehicleImage.DoesNotExist:
            return Response(
                {"detail": "Image not found"},
                status=status.HTTP_404_NOT_FOUND
            )


class PublicVehicleViewSet(viewsets.ReadOnlyModelViewSet):
    """Public read-only access to vehicles."""
    
    queryset = Vehicle.objects.filter(is_published=True).prefetch_related("images")
    serializer_class = VehicleSerializer
    permission_classes = []
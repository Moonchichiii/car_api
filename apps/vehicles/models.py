"""Models for the vehicles app."""

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from cloudinary.models import CloudinaryField


class Vehicle(models.Model):
    """Simple vehicle model for car rental."""
    
    make = models.CharField(_("make"), max_length=50)
    model = models.CharField(_("model"), max_length=50)
    year = models.PositiveIntegerField(
        _("year"),
        validators=[
            MinValueValidator(1900),
            MaxValueValidator(timezone.now().year + 1)
        ]
    )
    price_per_day = models.DecimalField(
        _("price per day"),
        max_digits=8,
        decimal_places=2,
        validators=[MinValueValidator(0.01)]
    )
    is_published = models.BooleanField(_("published"), default=False)
    description = models.TextField(_("description"), blank=True)
    
    # Metadata
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)
    
    class Meta:
        verbose_name = _("vehicle")
        verbose_name_plural = _("vehicles")
        ordering = ["-created_at"]
    
    def __str__(self):
        return f"{self.year} {self.make} {self.model}"


class VehicleImage(models.Model):
    """Vehicle images managed through Cloudinary."""
    
    vehicle = models.ForeignKey(
        Vehicle,
        on_delete=models.CASCADE,
        related_name="images"
    )
    image = CloudinaryField(
        "vehicle_image",
        folder="vehicles",
        transformation=[
            {"width": 800, "height": 600, "crop": "limit"},
            {"quality": "auto"},
            {"fetch_format": "auto"}
        ]
    )
    alt_text = models.CharField(_("alt text"), max_length=100)
    is_main = models.BooleanField(_("main image"), default=False)
    
    class Meta:
        verbose_name = _("vehicle image")
        verbose_name_plural = _("vehicle images")
        ordering = ["-is_main", "id"]
    
    def __str__(self):
        return f"Image for {self.vehicle}"
    
    def save(self, *args, **kwargs):
        if self.is_main:            
            VehicleImage.objects.filter(
                vehicle=self.vehicle,
                is_main=True
            ).exclude(pk=self.pk).update(is_main=False)
        super().save(*args, **kwargs)
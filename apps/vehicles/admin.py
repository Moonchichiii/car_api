"""Admin configuration for the vehicles app."""

from django.contrib import admin
from django.utils.html import mark_safe
from django.utils.translation import gettext_lazy as _
from .models import Vehicle, VehicleImage


class VehicleImageInline(admin.TabularInline):
    """Inline admin for vehicle images."""
    model = VehicleImage
    extra = 1
    readonly_fields = ("image_preview",)
    
    def image_preview(self, obj):
        if obj.image:
            return mark_safe(f'<img src="{obj.image.url}" style="height: 100px;">')
        return "-"
    image_preview.short_description = _("Preview")


@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    """Admin interface for vehicles."""
    
    list_display = ("__str__", "price_per_day", "is_published", "created_at")
    list_filter = ("is_published", "year", "make")
    search_fields = ("make", "model", "description")
    date_hierarchy = "created_at"
    
    fields = (
        "make", "model", "year", "price_per_day", 
        "description", "is_published"
    )
    
    inlines = [VehicleImageInline]
    
    # Instant publish/unpublish actions
    actions = ["publish_vehicles", "unpublish_vehicles"]
    
    def publish_vehicles(self, request, queryset):
        """Publish selected vehicles."""
        count = queryset.update(is_published=True)
        self.message_user(request, _(f"{count} vehicles published"))
    publish_vehicles.short_description = _("Publish selected vehicles")
    
    def unpublish_vehicles(self, request, queryset):
        """Unpublish selected vehicles."""
        count = queryset.update(is_published=False)
        self.message_user(request, _(f"{count} vehicles unpublished"))
    unpublish_vehicles.short_description = _("Unpublish selected vehicles")
    
    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("images")


@admin.register(VehicleImage)
class VehicleImageAdmin(admin.ModelAdmin):
    """Admin interface for vehicle images."""
    
    list_display = ("vehicle", "alt_text", "is_main", "image_preview")
    list_filter = ("is_main",)
    search_fields = ("vehicle__make", "vehicle__model", "alt_text")
    
    def image_preview(self, obj):
        if obj.image:
            return mark_safe(f'<img src="{obj.image.url}" style="height: 100px;">')
        return "-"
    image_preview.short_description = _("Preview")
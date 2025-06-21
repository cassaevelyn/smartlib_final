from django.contrib import admin
from django.utils.html import format_html
from .models import (
    SubscriptionPlan, UserSubscription, SubscriptionTransaction,
    SubscriptionBenefit, PlanBenefit
)


class PlanBenefitInline(admin.TabularInline):
    model = PlanBenefit
    extra = 1
    fields = ['benefit', 'value', 'is_available']


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'plan_type', 'price_display', 'billing_period',
        'is_active', 'is_featured', 'created_at'
    ]
    list_filter = ['plan_type', 'billing_period', 'is_active', 'is_featured']
    search_fields = ['name', 'code', 'description']
    readonly_fields = ['code', 'created_at', 'updated_at']
    inlines = [PlanBenefitInline]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'code', 'plan_type', 'description')
        }),
        ('Pricing', {
            'fields': ('price', 'discount_percentage', 'billing_period')
        }),
        ('Limits', {
            'fields': (
                'max_book_reservations', 'max_seat_bookings',
                'max_event_registrations', 'max_concurrent_digital_access'
            )
        }),
        ('Access Control', {
            'fields': (
                'has_premium_seat_access', 'has_premium_book_access',
                'has_premium_event_access'
            )
        }),
        ('Status & Display', {
            'fields': ('is_active', 'is_featured', 'color', 'icon')
        }),
        ('Features', {
            'fields': ('features',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def price_display(self, obj):
        if obj.discount_percentage > 0:
            return format_html(
                '<span style="text-decoration: line-through; color: gray;">PKR {}</span> '
                '<span style="color: green; font-weight: bold;">PKR {}</span> '
                '<span style="color: red;">(-{}%)</span>',
                obj.price, obj.discounted_price, obj.discount_percentage
            )
        return f'PKR {obj.price}'
    price_display.short_description = 'Price'


@admin.register(UserSubscription)
class UserSubscriptionAdmin(admin.ModelAdmin):
    list_display = [
        'subscription_code', 'user', 'plan', 'status',
        'start_date', 'end_date', 'payment_status', 'amount_paid'
    ]
    list_filter = ['status', 'payment_status', 'plan', 'is_auto_renew']
    search_fields = ['subscription_code', 'user__email', 'user__first_name', 'user__last_name']
    readonly_fields = ['subscription_code', 'created_at', 'updated_at']
    date_hierarchy = 'start_date'
    
    fieldsets = (
        ('Subscription Information', {
            'fields': ('user', 'plan', 'subscription_code', 'status')
        }),
        ('Dates', {
            'fields': ('start_date', 'end_date', 'cancelled_at')
        }),
        ('Payment', {
            'fields': (
                'amount_paid', 'payment_status', 'payment_method',
                'payment_reference'
            )
        }),
        ('Settings', {
            'fields': ('is_auto_renew', 'notes', 'metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['activate_subscriptions', 'cancel_subscriptions', 'mark_payment_completed']
    
    def activate_subscriptions(self, request, queryset):
        updated = queryset.update(status='ACTIVE')
        self.message_user(request, f'{updated} subscriptions activated.')
    activate_subscriptions.short_description = 'Activate selected subscriptions'
    
    def cancel_subscriptions(self, request, queryset):
        count = 0
        for subscription in queryset:
            if subscription.cancel():
                count += 1
        self.message_user(request, f'{count} subscriptions cancelled.')
    cancel_subscriptions.short_description = 'Cancel selected subscriptions'
    
    def mark_payment_completed(self, request, queryset):
        updated = queryset.filter(payment_status='PENDING').update(
            payment_status='COMPLETED'
        )
        self.message_user(request, f'{updated} subscriptions marked as paid.')
    mark_payment_completed.short_description = 'Mark selected subscriptions as paid'


@admin.register(SubscriptionTransaction)
class SubscriptionTransactionAdmin(admin.ModelAdmin):
    list_display = [
        'transaction_code', 'user', 'subscription', 'transaction_type',
        'amount', 'status', 'created_at'
    ]
    list_filter = ['transaction_type', 'status', 'payment_method', 'created_at']
    search_fields = [
        'transaction_code', 'user__email', 'user__first_name',
        'user__last_name', 'payment_reference'
    ]
    readonly_fields = ['transaction_code', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Transaction Information', {
            'fields': (
                'user', 'subscription', 'transaction_code',
                'transaction_type', 'status'
            )
        }),
        ('Amount', {
            'fields': ('amount', 'currency')
        }),
        ('Payment Details', {
            'fields': ('payment_method', 'payment_reference', 'payment_gateway')
        }),
        ('Additional Information', {
            'fields': ('notes', 'metadata')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_completed', 'mark_failed', 'mark_refunded']
    
    def mark_completed(self, request, queryset):
        updated = queryset.filter(status='PENDING').update(status='COMPLETED')
        self.message_user(request, f'{updated} transactions marked as completed.')
    mark_completed.short_description = 'Mark selected transactions as completed'
    
    def mark_failed(self, request, queryset):
        updated = queryset.filter(status='PENDING').update(status='FAILED')
        self.message_user(request, f'{updated} transactions marked as failed.')
    mark_failed.short_description = 'Mark selected transactions as failed'
    
    def mark_refunded(self, request, queryset):
        updated = queryset.filter(status='COMPLETED').update(status='REFUNDED')
        self.message_user(request, f'{updated} transactions marked as refunded.')
    mark_refunded.short_description = 'Mark selected transactions as refunded'


@admin.register(SubscriptionBenefit)
class SubscriptionBenefitAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'benefit_type', 'is_highlighted', 'sort_order'
    ]
    list_filter = ['benefit_type', 'is_highlighted']
    search_fields = ['name', 'description']
    ordering = ['sort_order', 'name']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'benefit_type', 'icon')
        }),
        ('Display', {
            'fields': ('is_highlighted', 'sort_order')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
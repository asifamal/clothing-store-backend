from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import Order


@receiver(pre_save, sender=Order)
def handle_order_status_change(sender, instance, **kwargs):
    """
    Handle stock management when order status changes
    """
    if not instance.pk:
        # New order, don't do anything
        return
    
    try:
        old_instance = Order.objects.get(pk=instance.pk)
    except Order.DoesNotExist:
        return
    
    old_status = old_instance.status
    new_status = instance.status
    
    print(f"Order #{instance.pk} status change: {old_status} → {new_status}")
    print(f"Stock already reduced: {instance.stock_reduced}")

    # Hard guard: once cancelled, status cannot change to anything else
    if old_status == 'cancelled' and new_status != 'cancelled':
        # Prevent changing status of a cancelled order
        # Raise an exception so API callers can return a proper error
        from django.core.exceptions import ValidationError
        raise ValidationError("Cannot change status of a cancelled order")
    
    # Prevent cancelling orders that are dispatched or delivered
    if new_status == 'cancelled' and old_status in ['dispatched', 'delivered']:
        from django.core.exceptions import ValidationError
        raise ValidationError(f"Cannot cancel an order that has been {old_status}. Please contact the customer to arrange a return.")
    
    # If order is being confirmed and stock hasn't been reduced yet
    if new_status == 'confirmed' and not instance.stock_reduced:
        print(f"Reducing stock for order #{instance.pk}")
        reduce_stock_for_order(instance)
        instance.stock_reduced = True
        
    # If order is being cancelled or moved back to pending, and stock was previously reduced
    elif (new_status in ['cancelled', 'pending']) and instance.stock_reduced:
        print(f"Restoring stock for order #{instance.pk}")
        restore_stock_for_order(instance)
        instance.stock_reduced = False
    
    # Send email notification when order is dispatched
    if new_status == 'dispatched' and old_status != 'dispatched':
        send_dispatch_notification(instance)


def reduce_stock_for_order(order):
    """Reduce product/variant stock when order is confirmed"""
    for item in order.items.all():
        print(f"Processing item: {item.product.name}, Size: {item.size}, Quantity: {item.quantity}")
        if item.size:
            # Reduce variant stock
            try:
                variant = item.product.variants.get(size=item.size)
                old_stock = variant.stock
                variant.stock = max(0, variant.stock - item.quantity)
                variant.save()
                print(f"  Variant {item.size} stock: {old_stock} → {variant.stock}")
                
                # Update main product stock to reflect total variant stock
                total_variant_stock = sum(v.stock for v in item.product.variants.all())
                item.product.stock = total_variant_stock
                item.product.save()
                print(f"  Main product stock updated to: {item.product.stock}")
            except item.product.variants.model.DoesNotExist:
                print(f"  Variant {item.size} not found!")
        else:
            # Reduce main product stock
            old_stock = item.product.stock
            item.product.stock = max(0, item.product.stock - item.quantity)
            item.product.save()
            print(f"  Product stock: {old_stock} → {item.product.stock}")


def restore_stock_for_order(order):
    """Restore product/variant stock when order is cancelled"""
    for item in order.items.all():
        if item.size:
            # Restore variant stock
            try:
                variant = item.product.variants.get(size=item.size)
                old_stock = variant.stock
                variant.stock += item.quantity
                variant.save()
                print(f"  Variant {item.size} stock restored: {old_stock} → {variant.stock}")
                
                # Update main product stock to reflect total variant stock
                total_variant_stock = sum(v.stock for v in item.product.variants.all())
                item.product.stock = total_variant_stock
                item.product.save()
                print(f"  Main product stock updated to: {item.product.stock}")
            except item.product.variants.model.DoesNotExist:
                print(f"  Variant {item.size} not found!")
        else:
            # Restore main product stock
            old_stock = item.product.stock
            item.product.stock += item.quantity
            item.product.save()
            print(f"  Product stock restored: {old_stock} → {item.product.stock}")


def send_dispatch_notification(order):
    """
    Send email notification when order is dispatched
    TODO: Implement actual email sending using Django's email backend
    For now, just print to console
    """
    print("="*50)
    print("ORDER DISPATCH NOTIFICATION EMAIL")
    print("="*50)
    print(f"To: {order.user.email}")
    print(f"Subject: Your Order #{order.id} Has Been Dispatched!")
    print(f"\nDear {order.user.first_name or order.user.username},")
    print(f"\nGreat news! Your order #{order.id} has been dispatched and is on its way to you.")
    print(f"\nOrder Details:")
    print(f"  Order ID: {order.id}")
    print(f"  Total Amount: ${order.total_amount}")
    print(f"  Status: Dispatched")
    
    # Shipping details
    if order.courier_partner or order.awb_number:
        print(f"\nShipping Details:")
        if order.courier_partner:
            print(f"  Courier Partner: {order.courier_partner}")
        if order.awb_number:
            print(f"  Tracking Number (AWB): {order.awb_number}")
    
    print(f"\nShipping Address:")
    if order.address:
        print(f"  {order.address.street_address}")
        print(f"  {order.address.city}, {order.address.state} {order.address.zip_code}")
        print(f"  {order.address.country}")
    print(f"\nOrder Items:")
    for item in order.items.all():
        size_info = f" (Size: {item.size})" if item.size else ""
        print(f"  - {item.product.name}{size_info} x {item.quantity} @ ${item.price} = ${item.total_price}")
    print(f"\nYou can expect delivery soon. Thank you for shopping with us!")
    print("="*50)
    print(f"\nYou can expect delivery soon. Thank you for shopping with us!")
    print("="*50)
    
    # TODO: Uncomment and configure when email is set up
    # from django.core.mail import send_mail
    # from django.template.loader import render_to_string
    # 
    # subject = f'Your Order #{order.id} Has Been Dispatched!'
    # 
    # # Create HTML email content
    # html_message = render_to_string('emails/order_dispatched.html', {
    #     'order': order,
    #     'user': order.user,
    #     'items': order.items.all(),
    # })
    # 
    # # Create plain text version
    # plain_message = f'''
    # Dear {order.user.first_name or order.user.username},
    # 
    # Great news! Your order #{order.id} has been dispatched and is on its way to you.
    # 
    # Order Details:
    # - Order ID: {order.id}
    # - Total Amount: ${order.total_amount}
    # - Status: Dispatched
    # 
    # You can expect delivery soon. Thank you for shopping with us!
    # '''
    # 
    # send_mail(
    #     subject=subject,
    #     message=plain_message,
    #     from_email='noreply@yourstore.com',
    #     recipient_list=[order.user.email],
    #     html_message=html_message,
    #     fail_silently=False,
    # )

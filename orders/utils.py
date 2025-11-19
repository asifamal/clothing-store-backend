import os
from io import BytesIO
from django.conf import settings
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from datetime import datetime


def generate_invoice_pdf(order):
    """
    Generate invoice PDF for an order
    Returns: BytesIO buffer containing the PDF
    """
    buffer = BytesIO()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18,
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name='CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        name='CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#333333'),
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name='CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=colors.HexColor('#666666'),
    ))
    styles.add(ParagraphStyle(
        name='RightAlign',
        parent=styles['BodyText'],
        fontSize=10,
        alignment=TA_RIGHT,
    ))
    
    # Add company header
    title = Paragraph("NOTED STORE", styles['CustomTitle'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Invoice title
    invoice_title = Paragraph(f"<b>INVOICE #{order.id}</b>", styles['CustomHeading'])
    elements.append(invoice_title)
    elements.append(Spacer(1, 12))
    
    # Order details
    order_info = [
        ['Order Date:', order.created_at.strftime('%B %d, %Y %I:%M %p')],
        ['Order Status:', order.status.upper()],
        ['Customer:', order.user.username],
        ['Email:', order.user.email],
    ]
    
    order_table = Table(order_info, colWidths=[2*inch, 4*inch])
    order_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#333333')),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#666666')),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(order_table)
    elements.append(Spacer(1, 20))
    
    # Shipping Address
    if order.address:
        address_heading = Paragraph("<b>Shipping Address:</b>", styles['CustomHeading'])
        elements.append(address_heading)
        
        address_text = f"{order.address.street_address}<br/>"
        address_text += f"{order.address.city}, {order.address.state} {order.address.zip_code}<br/>"
        address_text += f"{order.address.country}"
        
        address_para = Paragraph(address_text, styles['CustomBody'])
        elements.append(address_para)
        elements.append(Spacer(1, 20))
    
    # Order Items
    items_heading = Paragraph("<b>Order Items:</b>", styles['CustomHeading'])
    elements.append(items_heading)
    elements.append(Spacer(1, 12))
    
    # Items table
    items_data = [['Product', 'Quantity', 'Unit Price', 'Total']]
    
    for item in order.items.all():
        items_data.append([
            item.product.name,
            str(item.quantity),
            f"₹{item.price}",
            f"₹{item.total_price}"
        ])
    
    # Add totals
    items_data.append(['', '', 'Subtotal:', f"₹{order.total_amount}"])
    items_data.append(['', '', 'Tax:', '₹0.00'])
    items_data.append(['', '', 'Shipping:', '₹0.00'])
    
    # Create bold style for totals
    bold_style = ParagraphStyle(
        name='BoldRight',
        parent=styles['CustomBody'],
        fontName='Helvetica-Bold',
        alignment=TA_RIGHT,
    )
    
    items_data.append([
        '', 
        '', 
        Paragraph('<b>Total:</b>', styles['CustomBody']), 
        Paragraph(f"<b>₹{order.total_amount}</b>", bold_style)
    ])
    
    items_table = Table(items_data, colWidths=[3*inch, 1*inch, 1.5*inch, 1.5*inch])
    items_table.setStyle(TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#333333')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        
        # Data rows
        ('FONTNAME', (0, 1), (-1, -5), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -5), 9),
        ('TEXTCOLOR', (0, 1), (-1, -5), colors.HexColor('#666666')),
        ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        
        # Grid
        ('GRID', (0, 0), (-1, -5), 0.5, colors.HexColor('#e0e0e0')),
        
        # Totals section
        ('LINEABOVE', (2, -4), (-1, -4), 1, colors.HexColor('#333333')),
        ('FONTNAME', (2, -1), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (2, -4), (-1, -1), 10),
        ('TEXTCOLOR', (2, -4), (-1, -1), colors.HexColor('#333333')),
    ]))
    elements.append(items_table)
    elements.append(Spacer(1, 30))
    
    # Footer
    footer_text = """
    <para alignment="center">
    <b>Thank you for your order!</b><br/>
    For any questions, please contact us at support@notedstore.com<br/>
    <br/>
    This is a computer-generated invoice and does not require a signature.
    </para>
    """
    footer = Paragraph(footer_text, styles['CustomBody'])
    elements.append(footer)
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF data
    pdf_data = buffer.getvalue()
    buffer.close()
    
    return pdf_data


def save_invoice_pdf(order):
    """
    Generate and save invoice PDF to media folder
    Returns: relative path to the saved PDF
    """
    # Create invoices directory if it doesn't exist
    invoices_dir = os.path.join(settings.MEDIA_ROOT, 'invoices')
    os.makedirs(invoices_dir, exist_ok=True)
    
    # Generate filename
    filename = f"invoice_{order.id}_{order.created_at.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(invoices_dir, filename)
    
    # Generate PDF
    pdf_data = generate_invoice_pdf(order)
    
    # Save to file
    with open(filepath, 'wb') as f:
        f.write(pdf_data)
    
    # Return relative path
    return f"invoices/{filename}"

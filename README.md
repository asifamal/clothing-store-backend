# Clothing Store Backend API

A complete Django backend for a Clothing Store application with JWT authentication, role-based access control, and PostgreSQL database.

## Features

- **JWT Authentication** using `djangorestframework-simplejwt`
- **Role-based Access Control** (Manager and Customer)
- **Manual JSON Handling** (no DRF serializers)
- **PostgreSQL Database**
- **Product Management** with image uploads
- **Shopping Cart** functionality
- **Order Management** with status tracking
- **Admin Dashboard** with analytics

## Project Structure

```
clothingstore/
├── users/          # User management and authentication
├── products/       # Product and category management
├── cart/           # Shopping cart functionality
├── orders/         # Order processing and management
├── filters/        # Product filters and attributes
└── clothingstore/  # Main project settings
```

## Setup Instructions

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Create a `.env` file in the `backend/clothingstore/` directory:

```env
SECRET_KEY=your-secret-key-here
DEBUG=True

DB_NAME=clothingstore_db
DB_USER=postgres
DB_PASSWORD=your-database-password
DB_HOST=localhost
DB_PORT=5432
```

### 3. Database Setup

Make sure PostgreSQL is running and create the database:

```sql
CREATE DATABASE clothingstore_db;
```

### 4. Run Migrations

```bash
cd backend/clothingstore
python manage.py makemigrations
python manage.py migrate
```

### 5. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

### 6. Run Server

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000/`

## API Endpoints

### Authentication

#### Register User
- **POST** `/api/register/`
- **Body:**
  ```json
  {
    "username": "john_doe",
    "email": "john@example.com",
    "password": "password123",
    "role": "customer"  // or "manager"
  }
  ```

#### Login
- **POST** `/api/login/`
- **Body:**
  ```json
  {
    "username": "john_doe",
    "password": "password123"
  }
  ```
- **Response:** Returns JWT access and refresh tokens

#### Reset Password
- **POST** `/api/reset-password/`
- **Body:**
  ```json
  {
    "username": "john_doe",  // or "email": "john@example.com"
    "new_password": "newpassword123"
  }
  ```

### Products

#### List Products
- **GET** `/api/products/`
- **Query Parameters:**
  - `page` (default: 1)
  - `limit` (default: 10)
  - `category_id` (optional)
  - `search` (optional)

#### Add Product (Manager Only)
- **POST** `/api/products/add/`
- **Headers:** `Authorization: Bearer <token>`
- **Body (multipart/form-data):**
  ```json
  {
    "name": "T-Shirt",
    "description": "Cotton T-Shirt",
    "price": 29.99,
    "stock": 100,
    "category_id": 1,
    "image": <file>
  }
  ```

#### Update Product (Manager Only)
- **PUT** `/api/products/<id>/`
- **Headers:** `Authorization: Bearer <token>`
- **Body:** JSON with fields to update

#### Delete Product (Manager Only)
- **DELETE** `/api/products/<id>/`
- **Headers:** `Authorization: Bearer <token>`

#### List Categories
- **GET** `/api/products/categories/`

### Cart

#### Get Cart
- **GET** `/api/cart/`
- **Headers:** `Authorization: Bearer <token>`

#### Add to Cart
- **POST** `/api/cart/add/`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "product_id": 1,
    "quantity": 2
  }
  ```

#### Update Cart Item
- **PUT** `/api/cart/<item_id>/`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "quantity": 3
  }
  ```

#### Remove from Cart
- **DELETE** `/api/cart/<item_id>/`
- **Headers:** `Authorization: Bearer <token>`

### Orders

#### Place Order
- **POST** `/api/orders/place/`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "address_id": 1,  // or provide address details
    "street_address": "123 Main St",
    "city": "New York",
    "state": "NY",
    "zip_code": "10001",
    "country": "USA"
  }
  ```

#### List Customer Orders
- **GET** `/api/orders/`
- **Headers:** `Authorization: Bearer <token>`
- **Query Parameters:**
  - `page` (default: 1)
  - `limit` (default: 10)

#### List All Orders (Manager Only)
- **GET** `/api/orders/admin/`
- **Headers:** `Authorization: Bearer <token>`
- **Query Parameters:**
  - `page` (default: 1)
  - `limit` (default: 10)
  - `status` (optional filter)

#### Update Order Status (Manager Only)
- **PATCH** `/api/orders/admin/<order_id>/status/`
- **Headers:** `Authorization: Bearer <token>`
- **Body:**
  ```json
  {
    "status": "confirmed"  // placed, confirmed, dispatched, delivered, cancelled
  }
  ```

#### Admin Dashboard (Manager Only)
- **GET** `/api/orders/admin/dashboard/`
- **Headers:** `Authorization: Bearer <token>`
- **Response:**
  ```json
  {
    "status": "success",
    "data": {
      "total_users": 120,
      "total_orders": 45,
      "orders_by_status": {
        "placed": 20,
        "confirmed": 15,
        "dispatched": 10
      },
      "top_products": [
        {"name": "T-shirt", "sold": 25},
        {"name": "Jeans", "sold": 12}
      ]
    }
  }
  ```

## Authentication

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

To refresh the token, use the refresh token endpoint provided by `djangorestframework-simplejwt`.

## Response Format

All API responses follow this format:

```json
{
  "status": "success" | "error",
  "message": "Description message",
  "data": { ... }
}
```

## Role-Based Access

- **Manager**: Can add/update/delete products, view all orders, update order status, access admin dashboard
- **Customer**: Can browse products, manage cart, place orders, view own orders

## Database Models

- **User**: Custom user model with role field
- **Category**: Product categories
- **Product**: Products with price, stock, images
- **Filter, FilterOption, ProductFilterValue**: Product attributes (size, color, etc.)
- **Cart, CartItem**: Shopping cart
- **Order, OrderItem**: Orders and order items
- **CustomerAddress**: Shipping addresses

## Development Notes

- All JSON parsing is done manually using `json.loads(request.body)`
- No DRF serializers are used (except for JWT authentication)
- Media files are served from `/media/` in development
- CORS is configured for common frontend ports

## Testing

To test the API, you can use tools like:
- Postman
- curl
- httpie
- Your frontend application

Example curl command:

```bash
curl -X POST http://localhost:8000/api/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "password123"}'
```


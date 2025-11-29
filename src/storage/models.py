


class User:
    def __init__(self, user_id: int, username: str, email: str):
        """"Initialize a User object."""
        self.user_id = user_id
        self.username = username
        self.email = email

    def __repr__(self):
        """Return a string representation of the User object."""
        return f"User(user_id={self.user_id}, username='{self.username}', email='{self.email}')"

class Product:
    def __init__(self, product_id: int, name: str, price: float):
        """Initialize a Product object."""
        self.product_id = product_id
        self.name = name
        self.price = price

    def __repr__(self):
        """Return a string representation of the Product object."""
        return f"Product(product_id={self.product_id}, name='{self.name}', price={self.price})"
    

class Order:
    def __init__(self, order_id: int, user: User, product: Product, quantity: int):
        """Initialize an Order object."""
        self.order_id = order_id
        self.user = user
        self.product = product
        self.quantity = quantity

    def __repr__(self):
        """Return a string representation of the Order object."""
        return (f"Order(order_id={self.order_id}, user={self.user}, "
                f"product={self.product}, quantity={self.quantity})")

class InventoryItem:
    def __init__(self, item_id: int, product: Product, stock: int):
        """Initialize an InventoryItem object."""
        self.item_id = item_id
        self.product = product
        self.stock = stock

    def __repr__(self):
        """Return a string representation of the InventoryItem object."""
        return (f"InventoryItem(item_id={self.item_id}, product={self.product}, "
                f"stock={self.stock})")
    


    
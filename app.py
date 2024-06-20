from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
from forms import RegistrationForm, LoginForm
from flask import render_template, redirect, url_for, flash, request, session
from flask_migrate import Migrate

app = Flask(__name__)
app.config['STATIC_FOLDER'] = 'static'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    category = db.Column(db.String(10), nullable=False)
    item_category = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(10), nullable=False)
    size = db.Column(db.String(10), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/women')
def women():
    products = Product.query.filter_by(category='női').all()
    return render_template('women.html', products=products)

@app.route('/men')
def men():
    products = Product.query.filter_by(category='férfi').all()
    return render_template('men.html', products=products)

@app.route('/product/<int:product_id>', methods=['GET', 'POST'])
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/cart')
def cart():
    if 'cart' not in session or not session['cart']:
        flash('A kosár jelenleg üres.', 'info')
        return render_template('cart.html', items=[], total_price=0)

    items = session['cart']
    total_price = sum(item['total_price'] for item in items)
    return render_template('cart.html', items=items, total_price=total_price)


@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        size = request.form['size']
        quantity = int(request.form['quantity'])

        if 'cart' not in session:
            session['cart'] = []

        session['cart'].append({
            'product_id': product.id,
            'name': product.name,
            'category': product.category,
            'size': size,
            'quantity': quantity,
            'price': product.price,
            'total_price': product.price * quantity
        })

        flash('A termék sikeresen hozzá lett adva a kosárhoz.', 'success')
        return redirect(url_for('cart'))

    return redirect(url_for('product_detail', product_id=product.id))

@app.route('/remove_from_cart/<int:index>', methods=['POST'])
def remove_from_cart(index):
    if 'cart' not in session or not session['cart']:
        return redirect(url_for('cart'))

    if 0 <= index < len(session['cart']):
        session['cart'].pop(index)
        flash('A termék sikeresen eltávolítva a kosárból.', 'success')

    return redirect(url_for('cart'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)  # Jelszó titkosítása bcrypt segítségével
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):  # Jelszó ellenőrzése bcrypt segítségével
            session['user_id'] = user.id
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('home'))

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        flash('Be kell jelentkezned a rendelés leadásához.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    items = session.get('cart', [])
    if not items:
        flash('A kosár üres.', 'danger')
        return redirect(url_for('cart'))

    total_price = sum(item['total_price'] for item in items)
    new_order = Order(user_id=user_id, total_price=total_price)
    db.session.add(new_order)
    db.session.commit()

    for item in items:
        order_item = OrderItem(
            order_id=new_order.id,
            product_id=item['product_id'],
            name=item['name'],
            category=item['category'],
            size=item['size'],
            quantity=item['quantity'],
            price=item['price']
        )
        db.session.add(order_item)

    db.session.commit()

    session.pop('cart', None)
    flash('A rendelés sikeresen leadva!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)







import psycopg2
from flask import Flask, render_template, redirect, url_for, flash, request, session

from forms import LoginForm, RegisterForm, TicketForm, CommentForm
from db import query_db, execute_db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, Comment, Ticket
from utils import role_required
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object('config.Config')
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.get_user_by_id(user_id)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/protected')
@login_required
def protected():
    return "This is a protected page."


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form, csrf_enabled=False)
    if form.validate_on_submit():
        email = form.email.data
        username = form.username.data
        password = form.password.data

        if User.validate_user_registration(username, email):
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        User.create_user(email=email, username=username, password=hashed_password)
        return redirect(url_for('login'))
    print(form.errors)
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.validate_user_login(bcrypt, email, password)
        if user is not None:
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if not current_user.is_authenticated:
        flash('Please log in to view tickets.', 'danger')
        return redirect(url_for('login'))

    form = TicketForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        category_id = form.category.data
        priority_id = form.priority.data
        creator_id = current_user.id

        execute_db('INSERT INTO tickets (title, description, category_id, priority_id, creator_id, status_id) '
                   'VALUES (%s, %s, %s, %s, %s, %s)',
                   (title, description, category_id, priority_id, creator_id, 1))  # Status 1 = Open
        flash('Ticket created successfully.', 'success')
        return redirect(url_for('tickets'))

    tickets = query_db(
        'SELECT tickets.id, tickets.title, '
        'statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id and users.role_id = 1 '
        'WHERE tickets.creator_id = %s', (current_user.id,))
    return render_template('tickets.html', form=form, tickets=tickets)


@app.route('/tickets/<int:ticket_id>', methods=['GET', 'POST'])
def ticket(ticket_id):
    if not current_user.is_authenticated:
        flash('Please log in to view and add comments.', 'danger')
        return redirect(url_for('login'))

    ticket = query_db(
        'SELECT tickets.*, statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id and users.role_id = 1 '
        'WHERE tickets.id = %s', (ticket_id,), one=True)
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets'))
    form = CommentForm(request.form)
    if form.validate_on_submit():
        content = form.content.data
        if content:
            Comment.create_comment(ticket_id, current_user.id, content)

    comments = query_db(
        'SELECT comments.content, comments.created_at, users.username '
        'FROM comments '
        'JOIN users ON comments.author_id = users.id and users.role_id = 1 '
        'WHERE comments.ticket_id = %s '
        'ORDER BY comments.created_at DESC', (ticket_id,)
    )

    answers = query_db(
        'SELECT comments.content, comments.created_at, users.username '
        'FROM comments '
        'JOIN users ON comments.author_id = users.id and users.role_id = 2 '
        'WHERE comments.ticket_id = %s '
        'ORDER BY comments.created_at DESC', (ticket_id,)
    )
    return render_template('ticket.html', ticket=ticket, comments=comments, answers=answers, form=form)


@app.route('/tickets/create_ticket', methods=['GET', 'POST'])
def create_ticket():
    if not current_user.is_authenticated:
        flash('Please log in to view and add comments.', 'danger')
        return redirect(url_for('login'))

    category_choices = query_db(
        'SELECT categories.id, categories.name '
        'FROM categories '
    )

    priority_choices = query_db(
        'SELECT priorities.id, priorities.name '
        'FROM priorities '
    )

    form = TicketForm(request.form)
    form.category.choices = category_choices
    form.priority.choices = priority_choices
    if form.validate_on_submit():
        Ticket.create_ticket(form.title.data, form.description.data, form.priority.data,
                             form.category.data, current_user.id)
        return redirect(url_for('tickets'))

    return render_template('create_ticket.html', form=form, categories=category_choices, priorities=priority_choices)


@app.route('/admin/users')
@login_required
@role_required(1)
def manage_users():
    users = query_db(
        'SELECT users.id, users.username, users.email, roles.name AS role '
        'FROM users '
        'JOIN roles ON users.role_id = roles.id'
    )
    return render_template('admin_users.html', users=users)


@app.route('/categories', methods=['GET', 'POST'])
def categories():
    if 'user_id' not in session:
        flash('Please log in to manage categories.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            existing_category = query_db('SELECT * FROM categories WHERE name = %s', (name,), one=True)
            if existing_category:
                flash('Category already exists.', 'danger')
            else:
                execute_db('INSERT INTO categories (name) VALUES (%s)', (name,))
                flash('Category added successfully.', 'success')
        else:
            flash('Category name is required.', 'danger')

    categories = query_db('SELECT * FROM categories')
    return render_template('categories.html', categories=categories)


@app.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
def edit_category(category_id):
    if 'user_id' not in session:
        flash('Please log in to manage categories.', 'danger')
        return redirect(url_for('login'))

    category = query_db('SELECT * FROM categories WHERE id = %s', (category_id,), one=True)
    if not category:
        flash('Category not found.', 'danger')
        return redirect(url_for('categories'))

    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            execute_db('UPDATE categories SET name = %s WHERE id = %s', (name, category_id))
            flash('Category updated successfully.', 'success')
            return redirect(url_for('categories'))
        else:
            flash('Category name is required.', 'danger')

    return render_template('edit_category.html', category=category)


@app.route('/categories/delete/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if 'user_id' not in session:
        flash('Please log in to manage categories.', 'danger')
        return redirect(url_for('login'))

    category = query_db('SELECT * FROM categories WHERE id = %s', (category_id,), one=True)
    if not category:
        flash('Category not found.', 'danger')
    else:
        execute_db('DELETE FROM categories WHERE id = %s', (category_id,))
        flash('Category deleted successfully.', 'success')

    return redirect(url_for('categories'))


@app.route('/tickets/<int:ticket_id>/comments', methods=['GET', 'POST'])
def comments(ticket_id):
    if not current_user.is_authenticated:
        flash('Please log in to view and add comments.', 'danger')
        return redirect(url_for('login'))

    ticket = query_db('SELECT * FROM tickets WHERE id = %s', (ticket_id,), one=True)
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets'))

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            execute_db('INSERT INTO comments (ticket_id, author_id, content) VALUES (%s, %s, %s)',
                       (ticket_id, session['user_id'], content))
            flash('Comment added successfully.', 'success')
        else:
            flash('Comment content is required.', 'danger')

    comments = query_db(
        'SELECT comments.*, users.username '
        'FROM comments '
        'JOIN users ON comments.author_id = users.id '
        'WHERE comments.ticket_id = %s '
        'ORDER BY comments.created_at DESC', (ticket_id,)
    )
    return render_template('comments.html', ticket=ticket, comments=comments)


@app.route('/comments/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'user_id' not in session:
        flash('Please log in to delete comments.', 'danger')
        return redirect(url_for('login'))

    comment = query_db('SELECT * FROM comments WHERE id = %s', (comment_id,), one=True)
    if not comment:
        flash('Comment not found.', 'danger')
        return redirect(url_for('tickets'))

    if comment['author_id'] != session['user_id']:
        flash('You do not have permission to delete this comment.', 'danger')
    else:
        execute_db('DELETE FROM comments WHERE id = %s', (comment_id,))
        flash('Comment deleted successfully.', 'success')

    return redirect(url_for('comments', ticket_id=comment['ticket_id']))


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8001, debug=True)

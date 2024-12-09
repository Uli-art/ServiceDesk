import psycopg2
from flask import Flask, render_template, redirect, url_for, flash, request, session

from forms import LoginForm, RegisterForm, TicketForm, CommentForm, UpdateTicketForm, UpdateStatusForm
from db import query_db, execute_db
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import User, Comment, Ticket, ActivityLogs
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

        if not User.validate_user_registration(username, email):
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        User.create_user(email=email, username=username, password=hashed_password)
        user = User.validate_user_login(bcrypt, email, password)
        if user is not None:
            login_user(user)
            ActivityLogs.add_log(current_user.id, "registration")
            return redirect(url_for('index'))

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
            ActivityLogs.add_log(current_user.id, "login")
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    ActivityLogs.add_log(current_user.id, "logout")
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/tickets', methods=['GET', 'POST'])
@login_required
def tickets():
    ActivityLogs.add_log(current_user.id, "get tickets")

    form = TicketForm()
    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        category_id = form.category.data
        priority_id = form.priority.data
        creator_id = current_user.id

        Ticket.create_ticket(title, description, category_id, priority_id, creator_id, 1)
        ActivityLogs.add_log(current_user.id, "create ticket")
        flash('Ticket created successfully.', 'success')
        return redirect(url_for('tickets'))

    tickets = query_db(
        'SELECT tickets.id, tickets.title, '
        'statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id '
        'WHERE tickets.creator_id = %s', (current_user.id,))
    return render_template('tickets.html', form=form, tickets=tickets)


@app.route('/tickets/<int:ticket_id>', methods=['GET', 'POST'])
def ticket(ticket_id):

    form = CommentForm(request.form)
    if form.validate_on_submit():
        if current_user.is_authenticated:
            content = form.content.data
            if content:
                Comment.create_comment(ticket_id, current_user.id, content)
                ActivityLogs.add_log(current_user.id, "add comment", ticket_id)
        else:
            return redirect(url_for('login'))

    statuses_choices = query_db(
        'SELECT statuses.id, statuses.name '
        'FROM statuses '
    )

    updateForm = UpdateStatusForm(request.form)
    updateForm.status.choices = statuses_choices
    if updateForm.validate_on_submit():
        status = updateForm.status.data
        Ticket.update_ticket_status(status, ticket_id)
        ActivityLogs.add_log(current_user.id, "update status for ticket", ticket_id)

    ticket = query_db(
        'SELECT tickets.id, tickets.title, tickets.description, tickets.status_id,  DATE(tickets.created_at), '
        'statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id '
        'WHERE tickets.id = %s', (ticket_id,), one=True)
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets'))

    comments = query_db(
        'SELECT comments.content, DATE(comments.created_at), users.username '
        'FROM comments '
        'JOIN users ON comments.author_id = users.id and users.role_id = 1 '
        'WHERE comments.ticket_id = %s '
        'ORDER BY comments.created_at DESC', (ticket_id,)
    )

    answers = query_db(
        'SELECT comments.content, DATE(comments.created_at), users.username '
        'FROM comments '
        'JOIN users ON comments.author_id = users.id and users.role_id = 2 '
        'WHERE comments.ticket_id = %s '
        'ORDER BY comments.created_at DESC', (ticket_id,)
    )

    is_mine = False
    if current_user.is_authenticated:
        is_mine = current_user.id == ticket[6]
    return render_template('ticket.html', ticket=ticket, comments=comments, answers=answers,
                           form=form, is_mine=is_mine, statuses=statuses_choices)


@app.route('/tickets/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():

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
        ActivityLogs.add_log(current_user.id, "create ticket")
        return redirect(url_for('tickets'))

    return render_template('create_ticket.html', form=form, categories=category_choices, priorities=priority_choices)


@app.route('/tickets/edit/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):

    ticket = query_db(
        'SELECT tickets.*, statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id '
        'WHERE tickets.id = %s', (ticket_id,), one=True)
    if not ticket:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('tickets'))

    category_choices = query_db(
        'SELECT categories.id, categories.name '
        'FROM categories '
    )

    priority_choices = query_db(
        'SELECT priorities.id, priorities.name '
        'FROM priorities '
    )

    form = UpdateTicketForm(request.form)
    form.category.choices = category_choices
    form.priority.choices = priority_choices
    if form.validate_on_submit():
        Ticket.update_ticket(form.title.data, form.description.data, form.priority.data,
                             form.category.data, current_user.id, ticket[3], ticket[0])
        ActivityLogs.add_log(current_user.id, "update ticket", ticket_id)
        return redirect(url_for('tickets'))

    return render_template('edit_ticket.html', form=form, categories=category_choices,
                           priorities=priority_choices, ticket=ticket)


@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    tickets_by_status = query_db('SELECT statuses.name, count FROM ('
                                 'SELECT status_id, COUNT(*) as count from tickets group by status_id) '
                                 'join statuses on statuses.id = status_id')

    tickets_by_priority = query_db('SELECT priorities.name, count FROM ('
                                   'SELECT priority_id, COUNT(*) as count from tickets group by priority_id) '
                                   'join priorities on priorities.id = priority_id')

    tickets_by_category = query_db('SELECT categories.name, count FROM ('
                                   'SELECT category_id, COUNT(*) as count from tickets group by category_id) '
                                   'join categories on categories.id = category_id')

    tickets_closed = query_db("""SELECT
                    DATE(DATE_TRUNC('week', created_at)) AS week_start,
                    COUNT(*) AS ticket_count
                FROM
                    tickets
                WHERE
                    created_at >= DATE_TRUNC('month', CURRENT_DATE)
                    AND created_at < DATE_TRUNC('month', CURRENT_DATE) + INTERVAL '1 month'
                    AND status_id = 3
                GROUP BY
                    week_start
                ORDER BY
                    week_start;
            """)

    tickets_opened = query_db("""SELECT
                    DATE(DATE_TRUNC('week', created_at)) AS week_start,
                    COUNT(*) AS ticket_count
                FROM
                    tickets
                WHERE
                    created_at >= DATE_TRUNC('month', CURRENT_DATE)
                    AND created_at < DATE_TRUNC('month', CURRENT_DATE) + INTERVAL '1 month'
                GROUP BY
                    week_start
                ORDER BY
                    week_start;
            """)

    top_solvers = query_db("""select users.username, ticket_count from (SELECT
                            assignee_id, COUNT(*) AS ticket_count
                        FROM
                            tickets
                        WHERE status_id = 3
                        GROUP BY
                            assignee_id
                        ORDER BY
                            ticket_count desc)
                        JOIN users on users.id = assignee_id limit 10;
          """)

    activities = query_db("""SELECT users.username, activity_logs.action, 
                            DATE(activity_logs.created_at), activity_logs.ticket_id
                            FROM activity_logs
                            JOIN users on users.id = user_id 
                            ORDER BY activity_logs.created_at DESC limit 20;
                            """)

    ActivityLogs.add_log(current_user.id, "see reports")
    return render_template('reports.html', tickets_by_status=dict(tickets_by_status),
                           tickets_by_priority=dict(tickets_by_priority), tickets_by_category=dict(tickets_by_category),
                           tickets_closed=dict(tickets_closed), tickets_opened=dict(tickets_opened),
                           top_solvers=top_solvers, activities=activities)


@app.route('/dashboard', methods=['GET'])
def dashboard():

    tickets = query_db(
        'SELECT tickets.id, tickets.title, '
        'statuses.name as status, priorities.name as priority, categories.name as category, users.username as creator '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.creator_id = users.id ')
    return render_template('tickets.html', tickets=tickets)


@app.route('/requests')
@login_required
@role_required(2)
def requests():
    tickets = query_db(
        'SELECT tickets.id, tickets.title, '
        'statuses.name as status, priorities.name as priority, categories.name as category, users.username as assignee '
        'FROM tickets '
        'JOIN statuses ON tickets.status_id = statuses.id '
        'JOIN priorities ON tickets.priority_id = priorities.id '
        'JOIN categories ON tickets.category_id = categories.id '
        'JOIN users ON tickets.assignee_id = users.id ')
    ActivityLogs.add_log(current_user.id, "see requests")
    return render_template('requests.html', tickets=tickets)


@app.route('/admin/users')
@login_required
@role_required(2)
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


@app.route('/comments/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):

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

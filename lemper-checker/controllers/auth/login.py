def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.verify(password, user.password):
            login_user(user)
            flash('Login successful!', 'success')
            session['logged_in'] = True  # Menyimpan status login dalam sesi
            return redirect(url_for('dashboard'))

        flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')
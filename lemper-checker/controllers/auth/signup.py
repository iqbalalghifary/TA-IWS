def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        student_id = request.form['student_id']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        hashed_password = bcrypt.hash(password)

        new_user = User(full_name=full_name, student_id=student_id, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')
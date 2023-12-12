def reset_password(token):
     # Decode the token to get the user's email
    user_email = decode_reset_token(token)

    if not user_email:
        flash("Invalid token.", 'error')
        return redirect(url_for('login'))

    # Find the user based on the email
    user = User.query.filter_by(email=user_email).first()

    if not user:
        flash("User not found.", 'error')
        return redirect(url_for('login'))

    # TODO: Implement password reset logic here

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            # Update the user's password in the database
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()

            flash("Password reset successfully.", 'success')
            return redirect(url_for('login'))
        else:
            flash("Passwords do not match.", 'error')

    return render_template('reset_password.html')
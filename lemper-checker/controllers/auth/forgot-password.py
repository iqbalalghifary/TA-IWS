def lupa_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a token for password reset
            token = generate_reset_token(user.email)

            # Send email with the reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"Reset Link: {reset_link}")

            message = Message("Password Reset", recipients=[user.email])
            message.body = f"Click the link to reset your password: {reset_link}"
        
            try:
                mail.send(message)
                flash("Password reset link sent to your email.")
            except Exception as e:
                flash(f"Error sending email: {str(e)}", 'error')
                app.logger.error(f"Error sending email: {str(e)}")

        else:
            flash("Email not found.", 'error')

    return render_template('lupa_password.html')
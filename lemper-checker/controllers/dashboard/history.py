def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Fetch all reports for the current user from the database
    user_reports = Report.query.filter_by(user_id=current_user.id).all()

    # Format the timestamp to a readable string
    formatted_reports = [
        {
            'id': report.id_report,
            'title': report.title_report,
            'status': report.status,
            'file': report.path_file,
            'tanggal': report.tanggal
        }
        for report in user_reports
    ]

    return render_template('dashboard.html', reports=formatted_reports)
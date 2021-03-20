import os
import secrets
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from flask_uploads import configure_uploads, IMAGES, UploadSet

from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import Form, StringField, RadioField, TextAreaField, PasswordField, SubmitField, validators
from wtforms.fields.html5 import DateField, EmailField
from wtforms.validators import DataRequired, InputRequired, Email

from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.datastructures import CombinedMultiDict

app = Flask(__name__)


# Config MySQL
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('DATABASE_PASSOWRD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['UPLOADED_IMAGES_DEST'] = 'static/images'
app.static_folder = 'static'

# init MYSQL
mysql = MySQL(app)


#People
@app.route('/')
def people():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get email,photo, bio
    result = cur.execute("SELECT photos.name, profiles.bio, profiles.email,photos.photo FROM photos JOIN profiles ON photos.email = profiles.email WHERE profiles.bio IS NOT NULL")

    profiles = cur.fetchall()

    if result > 0:
        return render_template('people.html', profiles=profiles) 
    else:
        msg = 'No People Found'
        return render_template('people.html', msg=msg)
    # Close connection
    cur.close()

#Single profile
@app.route('/people/<string:email>/')
def profile(email):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get Profils    
    result = cur.execute("SELECT * FROM photos JOIN profiles ON photos.email = profiles.email WHERE photos.email = %s", [email]) 
    profiles = cur.fetchall() 
    return render_template('profile.html', profiles=profiles)


#Search---------------------------------------------------------------------------

class SearchForm(Form):
   search = StringField('', [validators.Length(min=2, max=50)])

@app.route('/search', methods =['GET', 'POST'])
def search_result ():
    form = SearchForm(request.form)

    if request.method == "POST" and form.validate() :
        search = form.search.data 

        cur = mysql.connection.cursor() 
  

        search_var = '%' + search + '%'
        query = "SELECT photos.name, profiles.bio, profiles.email,photos.photo FROM photos JOIN profiles ON photos.email = profiles.email WHERE  (profiles.bio LIKE %s or photos.name LIKE %s)"
        result = cur.execute(query,(search_var, search_var ,))
        profiles = cur.fetchall()
        cur.close()

        return render_template('search.html', profiles = profiles, form = form)
    return render_template('search.html',  form = form)


#Register -------------------------------------------------------------------------------

class RegisterForm(Form):
    email = StringField('', [validators.Length(min=2, max=50), validators.Email()])
    password = PasswordField('', [
        validators.DataRequired(),
        validators.Length(min=8),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('')
    name = StringField('', [validators.Length(min=2, max=50)])

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data 
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(email, name, password) VALUES(%s, %s, %s)", (email, name, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('login/register.html', form=form)


#Login------------------------------------------------------------------

class LoginForm(Form):
    email = StringField('Email', [validators.Length(min=2, max=50), validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8)])

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)

    if request.method == 'POST' and  form.validate() :
        # Get Form Fields
        email = form.email.data 
        password_candidate = form.password.data 

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            name = data['name']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['email'] = email
                session['name'] = name

                flash('You are now logged in', 'success')
                return redirect(url_for('my_profile'))
            else:
                error = 'Invalid login or password'
                return render_template('login/login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Email not found'
            return render_template('login/login.html', error=error)

    return render_template('login/login.html', form = form)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


#My_profile 

@app.route('/my_profile')
@is_logged_in
def my_profile():

    # Create cursor
    cur = mysql.connection.cursor()
    

    # Get profiles "SELECT * FROM profiles WHERE email = %s"
    result = cur.execute("SELECT * FROM profiles INNER JOIN photos ON photos.email = profiles.email WHERE profiles.email = %s", [session['email']])
    profiles = cur.fetchall()

    if result > 0 :
        return render_template('my_profile.html', profiles=profiles)
    else:
        msg = 'Fill your profiles! :-) '
        return render_template('my_profile.html', msg=msg)
    # Close connection
    cur.close()

# Image -----------------------------------------------------------------------------------------------------------

images = UploadSet('images', IMAGES)
configure_uploads(app, images)

class PhotoForm(FlaskForm):
    image = FileField('image')
    
# Add Photo
@app.route('/add_photo', methods=['GET', 'POST'])
@is_logged_in
def add_photo():
    form = PhotoForm()
    if form.validate_on_submit():
        filename = images.save(form.image.data)

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO photos(photo,email,name) VALUES(%s, %s, %s)",  (filename, session['email'], session['name'])  )

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Photo Uploaded', 'success')
        return redirect(url_for('my_profile'))
    return render_template("add/add_photo.html", form=form)


# Edit Photo
@app.route('/edit_photo/<string:email>', methods=['GET', 'POST'])
@is_logged_in
def edit_photo(email):
    form = PhotoForm()
    if form.validate_on_submit():
        filename = images.save(form.image.data)

        # Create Cursor
        cur = mysql.connection.cursor()


        # Execute
        cur.execute("UPDATE photos SET photo = %s WHERE email=%s",(filename,email) )

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Photo Edited', 'success')
        return redirect(url_for('my_profile'))
    return render_template("edit/edit_photo.html", form=form)




# BIO ---------------------------------------------------------------

class BioForm(Form):
    bio = TextAreaField('',[validators.Length(min=5)])


# Add Bio
@app.route('/add_bio', methods=['GET', 'POST'])
@is_logged_in
def add_bio():
    form = BioForm(request.form)
    if request.method == 'POST' and form.validate():
        bio = form.bio.data
   
        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(bio, name, email) VALUES(%s, %s, %s)",(bio, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Bio Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_bio.html', form=form)


# Edit Bio
@app.route('/edit_bio/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_bio(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = BioForm(request.form)

    # Populate article form fields
    form.bio.data = profile['bio']

    if request.method == 'POST' and form.validate():
        bio = request.form['bio']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(bio)
        # Execute
        cur.execute ("UPDATE profiles SET bio = %s WHERE id=%s",(bio,id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Bio Edited', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_bio.html', form=form)


# Delete Bio
@app.route('/delete/<string:id>', methods=['POST'])
@is_logged_in
def delete(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM profiles WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    #Close connection
    cur.close()

    flash('Deleted About', 'success')

    return redirect(url_for('my_profile'))




# Experience Form Class-----------------------------------------------------------------------------------------------------------
class ExperienceForm(Form):
    experience_company = StringField('', [validators.Length(min=1)])
    experience_jobtitle = StringField('', [validators.Length(min=2)])
    experience_description = TextAreaField('', [validators.Length(min=5)])
    experience_start_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    experience_end_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))  
    

# Add Experience
@app.route('/add_experience', methods=['GET', 'POST'])
@is_logged_in
def add_experience():
    form = ExperienceForm(request.form)
    if request.method == 'POST' and form.validate():
        experience_company = form.experience_company.data
        experience_jobtitle = form.experience_jobtitle.data
        experience_description = form.experience_description.data
        experience_start_date = form.experience_start_date.data
        experience_end_date = form.experience_end_date.data
        

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(experience_company, experience_jobtitle, experience_description, experience_start_date, experience_end_date,  name, email) VALUES(%s, %s, %s, %s, %s, %s,%s)",(experience_company, experience_jobtitle, experience_description, experience_start_date, experience_end_date, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Experience Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_experience.html', form=form)


# Edit Experience
@app.route('/edit_experience/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_experience(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = ExperienceForm(request.form)

    # Populate experience form fields
    form.experience_company.data = profile['experience_company']
    form.experience_jobtitle.data = profile['experience_jobtitle']
    form.experience_description.data = profile['experience_description']
    form.experience_start_date.data = profile['experience_start_date']
    form.experience_end_date.data = profile['experience_end_date']

    if request.method == 'POST' and form.validate():
        experience_company = request.form['experience_company']
        experience_jobtitle = request.form['experience_jobtitle']
        experience_description = request.form['experience_description']
        experience_start_date = request.form['experience_start_date']
        experience_end_date = request.form['experience_end_date']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(experience_company)
        # Execute
        cur.execute ("UPDATE profiles SET experience_company = %s, experience_jobtitle = %s, experience_description = %s, experience_start_date = %s,experience_end_date = %s WHERE id=%s",(experience_company, experience_jobtitle, experience_description, experience_start_date, experience_end_date, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Experience Updated', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_experience.html', form=form)


# Project Form Class-----------------------------------------------------------------------------------------------------------
class ProjectForm(Form):
    project_name = StringField('', [validators.Length(min=1)])
    project_start_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    project_end_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))  
    project_description = TextAreaField('', [validators.Length(min=5)])

# Add Project
@app.route('/add_project', methods=['GET', 'POST'])
@is_logged_in
def add_project():
    form = ProjectForm(request.form)
    if request.method == 'POST' and form.validate():
        project_name = form.project_name.data
        project_start_date = form.project_start_date.data
        project_end_date = form.project_end_date.data
        project_description = form.project_description.data
        

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(project_name, project_start_date, project_end_date,  project_description, name, email) VALUES(%s, %s, %s, %s, %s,%s)",(project_name, project_start_date, project_end_date, project_description, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Experience Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_project.html', form=form)


# Edit Project
@app.route('/edit_project/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_project(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = ProjectForm(request.form)

    # Populate experience form fields
    form.project_name.data = profile['project_name']
    form.project_start_date.data = profile['project_start_date']
    form.project_end_date.data = profile['project_end_date']
    form.project_description.data = profile['project_description']

    if request.method == 'POST' and form.validate():
        project_name = request.form['project_name']
        project_start_date = request.form['project_start_date']
        project_end_date = request.form['project_end_date']
        project_description = request.form['project_description']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(project_name)
        # Execute
        cur.execute ("UPDATE profiles SET project_name = %s, project_start_date = %s, project_end_date = %s, project_description= %s WHERE id=%s",(project_name, project_start_date, project_end_date, project_description, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Project Updated', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_project.html', form=form)


# License Form Class-----------------------------------------------------------------------------------------------------------
class LicenseForm(Form):
    license_name = StringField('', [validators.Length(min=1)])
    license_provision = TextAreaField('', [validators.Length(min=5)])
    license_acquisition_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    

# Add License
@app.route('/add_license', methods=['GET', 'POST'])
@is_logged_in
def add_license():
    form = LicenseForm(request.form)
    if request.method == 'POST' and form.validate():
        license_name = form.license_name.data
        license_provision = form.license_provision.data
        license_acquisition_date = form.license_acquisition_date.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(license_name, license_provision, license_acquisition_date, name, email) VALUES(%s, %s, %s, %s, %s)",(license_name, license_provision, license_acquisition_date, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New License Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_license.html', form=form)

# Edit License
@app.route('/edit_license/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_license(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = LicenseForm(request.form)

    # Populate license form fields
    form.license_name.data = profile['license_name']
    form.license_acquisition_date.data = profile['license_acquisition_date']
    form.license_provision.data = profile['license_provision']

    if request.method == 'POST' and form.validate():
        license_name = request.form['license_name']
        license_acquisition_date = request.form['license_acquisition_date']
        license_provision = request.form['license_provision']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(license_name)
        # Execute
        cur.execute ("UPDATE profiles SET license_name = %s, license_acquisition_date = %s, license_provision = %s WHERE id=%s",(license_name, license_acquisition_date, license_provision, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New License Updated', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_license.html', form=form)





# Award Form Class-----------------------------------------------------------------------------------------------------------
class AwardForm(Form):
    award_name = StringField('', [validators.Length(min=1)])
    award_description = TextAreaField('', [validators.Length(min=5)])
    award_acquisition_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    

# Add Award
@app.route('/add_award', methods=['GET', 'POST'])
@is_logged_in
def add_award():
    form = AwardForm(request.form)
    if request.method == 'POST' and form.validate():
        award_name = form.award_name.data
        award_description = form.award_description.data
        award_acquisition_date = form.award_acquisition_date.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(award_name, award_description, award_acquisition_date, name, email) VALUES(%s, %s, %s, %s, %s)",(award_name, award_description, award_acquisition_date, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Award Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_award.html', form=form)



# Edit Award
@app.route('/edit_award/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_award(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = AwardForm(request.form)

    # Populate Award form fields
    form.award_name.data = profile['award_name']
    form.award_description.data = profile['award_description']
    form.award_acquisition_date.data = profile['award_acquisition_date']

    if request.method == 'POST' and form.validate():
        award_name = request.form['award_name']
        award_description = request.form['award_description']
        award_acquisition_date = request.form['award_acquisition_date']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(award_name)
        # Execute
        cur.execute ("UPDATE profiles SET award_name = %s, award_description = %s, award_acquisition_date = %s WHERE id=%s",(award_name, award_description, award_acquisition_date, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Award Updated', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_award.html', form=form)


# Education Form Class-----------------------------------------------------------------------------------------------------------
class EducationForm(Form):
    education_name = StringField('', [validators.Length(min=1)])
    education_choices = RadioField('', choices=[('재학중','재학중'),('학사졸업','학사졸업'),('석사졸업','석사졸업'),('박사졸업','박사졸업')])
    education_description = TextAreaField('', [validators.Length(min=5)])
    education_start_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    education_end_date = DateField('', format='%Y-%m-%d', validators=(validators.DataRequired(),))
   

# Add Education
@app.route('/add_education', methods=['GET', 'POST'])
@is_logged_in
def add_education():
    form = EducationForm(request.form)
    if request.method == 'POST' and form.validate():
        education_name = form.education_name.data
        education_choices = form.education_choices.data
        education_description = form.education_description.data
        education_start_date = form.education_start_date.data
        education_end_date = form.education_end_date.data


        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO profiles(education_name, education_choices, education_description, education_start_date, education_end_date, name, email) VALUES(%s, %s, %s, %s, %s, %s, %s)",(education_name, education_choices, education_description,education_start_date, education_end_date, session['name'], session['email']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Education Created', 'success')

        return redirect(url_for('my_profile'))

    return render_template('add/add_education.html', form=form)

# Edit Education
@app.route('/edit_education/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_education(id):
    # Create cursor
    cur = mysql.connection.cursor()
    # Get profile by id
    result = cur.execute("SELECT * FROM profiles WHERE id = %s", [id])

    profile = cur.fetchone()

    cur.close()

    # Get form
    form = EducationForm(request.form)

    # Populate education form fields
    form.education_name.data = profile['education_name']
    form.education_choices.data = profile['education_choices']
    form.education_description.data = profile['education_description']
    form.education_start_date.data = profile['education_start_date']
    form.education_end_date.data = profile['education_end_date']

    if request.method == 'POST' and form.validate():
        education_name = request.form['education_name']
        education_choices = request.form['education_choices']
        education_description = request.form['education_description']
        education_start_date = request.form['education_start_date']
        education_end_date = request.form['education_end_date']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(education_name)
        # Execute
        cur.execute ("UPDATE profiles SET education_name = %s, education_choices = %s, education_description = %s , education_start_date = %s , education_end_date = %s  WHERE id=%s",(education_name, education_choices, education_description, education_start_date,education_end_date,  id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('New Education Updated', 'success')

        return redirect(url_for('my_profile'))

    return render_template('edit/edit_education.html', form=form)



#About Connected
@app.route('/about_connected')
def about_connected():
    return render_template('about_connected.html')

if __name__ == '__main__':
    app.secret_key=os.getenv('MY_SECRET_KEY')
    app.run(debug=True)

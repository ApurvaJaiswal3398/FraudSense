from flask import Flask, render_template, request, redirect
from database import Transaction
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,scoped_session
from datetime import datetime
from flask_bcrypt import Bcrypt
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
from fraud_detection import predict
import pandas as pd
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Creating Flask App
app = Flask(__name__)

# Global Variables
logged_in = False   # To check if user is logged in or not
otp = None          # To store OTP for password reset
adminpass = None    # To store admin password
data = None         # To store data to be passed to html file
with open(r'pwd.pwd', 'r') as f:    # Reading admin password from file
    adminpass = f.read()
receiver = None     # To store receiver email for password reset
loginmsg = None     # To store login message
alert = None        # To store alert type
pschanged = False   # To check if password is changed or not

# Function to reset global variables
def noneall():
    global otp
    global adminpass
    global receiver
    global loginmsg
    global pschanged
    otp = receiver = loginmsg = None
    pschanged = False

#function to load database table into a pandas dataframe
def load_data():
    engine = create_engine('sqlite:///project.sqlite').connect()    # Creating Database Engine
    df = pd.read_sql_table('transactions', engine)  # Reading Database Table into Pandas DataFrame
    print(df.head())    # Printing DataFrame
    return df   # Returning DataFrame

# Function to get database session
def getdb():
    engine = create_engine('sqlite:///project.sqlite')  # Creating Database Engine
    DBSession = sessionmaker(bind=engine)   # Creating Session for Database
    session = scoped_session(DBSession) # Creating Scoped Session for Database
    return session

@app.route('/')
def index():
    print(f"Logged In : {logged_in}\nOTP : {otp}\nAdmin Pass : {adminpass}\nReceiver : {receiver}\nLogin Msg : {loginmsg}\nPassword Changed : {pschanged}")
    return redirect('/homepage')    # Redirecting to Homepage

@app.route('/login', methods=['GET','POST'])
def login():
    message = None      # To store error message
    global alert
    alert = 'danger'
    global logged_in
    global loginmsg
    global adminpass
    
    if request.method == "POST":
        login_email = request.form.get('login_email')       # Getting Email from Form
        login_password = request.form.get('login_password') # Getting Password from Form
        print("Login Detail : ",login_email, login_password)
        if login_email == 'jaiswal.apurva.aj011@gmail.com':  # Checking if admin email is correct
            if adminpass == login_password:    # Checking if admin password is correct
                print("Admin Login Successful")
                loginmsg = 'Admin Login Successful!'    # Setting Login Message
                alert = 'success'   # Setting Alert Type
                logged_in = True    # Setting Logged In to True
                return redirect('/')  # Redirecting to Dashboard
            else:   # If admin password is not correct
                print("Admin Password Not matched")
                message = 'Invalid Email or Password!'  # Setting Error Message
                logged_in = False   # Setting Logged In to False
        else:   # If admin email is not correct
            print("Invalid Username")
            message = 'Invalid Email or Password!'  # Setting Error Message
            logged_in = False   # Setting Logged In to False
    if not message and loginmsg:    # If Login Message is set
        message = loginmsg      # Setting Error Message
        alert = 'success'
        if pschanged:   # If Password is changed
            noneall()   # Resetting Global Variables
    print(f"Logged In : {logged_in}\nOTP : {otp}\nAdmin Pass : {adminpass}\nReceiver : {receiver}\nLogin Msg : {loginmsg}\nPassword Changed : {pschanged}")
    return render_template('login.html', title='Login', logged_in=logged_in, message=message, alert=alert)

# Function to generate and send customised email while resetting password
def send_mail(cpass):
    sender = 'jaiswal.apurva.aj011@gmail.com'   # Sender Email
    subject = 'FraudSense Account Password Reset OTP Mail'  # Subject of Email
    global otp
    otp = ''.join(random.choices(string.ascii_letters + string.digits, k=8))    # Generating OTP
    msg = '''<h4 style='color: #292b2c;'>FraudSense Account</h4>
        <big><h1 style='color: #0275d8;'>Password reset code</h1></big>
        <p>Please use this code to reset the password for the FraudSense account with email ''' + receiver + '''.</p><br>
        <p>Here is your code : <big><b>''' + otp + '''</b></big><br><br>Thanks.<br>The FraudSense Team</p>'''   # Message of Email
    success = False    # To check if email is sent or not
    m = MIMEMultipart('alternative')    # Creating MIME Message
    m['From'] = sender  # Setting Sender
    m['To'] = receiver  # Setting Receiver
    m['Subject'] = subject  # Setting Subject
    m.attach(MIMEText(msg,'html'))  # Attaching Message
    print(f'sender : {sender}\nReceiver : {receiver}\nOTP : {otp}\nMessage : {msg}\nSuccess : {success}\nMIME Content : {m}')

    con = smtplib.SMTP_SSL('smtp.gmail.com', 465)   # Creating SMTP Connection
    print('Connected to SMTP Server')
    try:    # Trying to Login
        con.login(sender, cpass)    # Logging In
        print('Logged In by Company Email')
        msg_content = m.as_string()     # Converting MIME Message to String
        print('Message Created for the Mail to be Sent : \n',msg_content)
        con.sendmail(sender, receiver, msg_content)     # Sending Mail
        print('Mail Sent')
        success = True  # Setting Success to True
    except smtplib.SMTPAuthenticationError:    # If Login Failed
        print('Wrong Company Password Entered!')
        otp = None  # Resetting OTP
        success = False # Setting Success to False
    finally:
        con.quit()  # Quitting SMTP Connection
        print('Logged out of the Company Mail')
        print('Sending Process Ended')
        return success  # Returning Success

# Function to reset password, if OTP is correct
def send_confirmation(cpass):
    sender = 'jaiswal.apurva.aj011@gmail.com'
    subject = 'FraudSense Account Password Change Confirmation'
    msg = '''<h4 style='color: #444444;'>FraudSense Account</h4>
    <big><h1 style='color: blue;'>Your Password is Changed</h1></big>
    <p>Your password for the FraudSense account '''+receiver+''' was changed on '''+datetime.now().strftime('%Y/%m/%d %H:%M:%S')+'''.</p>
    <p>Thanks,\nThe FraudSense Team.</p>'''
    success = False
    m = MIMEMultipart('alternative')
    m['From'] = sender
    m['Bcc'] = receiver
    m['Subject'] = subject
    m.attach(MIMEText(msg,'html'))
    print(f'sender : {sender}\nReceiver : {receiver}\nAdmin Password : {adminpass}\nMessage : {msg}\nSuccess : {success}\nMIME Content : {m}')

    con = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    print('Connected to SMTP Server via SSL')
    if cpass:   # If Password is not None
        print('Admn Password : ',cpass,' is OK')
        try:
            print('Logging In!')
            con.login(sender, cpass)    # Logging In
            print('Logged In by Comapny Email')
            msg_content = m.as_string()    # Converting MIME Message to String
            print('Message Created for the Mail to be Sent : \n',msg_content)
            con.sendmail(sender, receiver, msg_content)    # Sending Mail
            print('Mail Sent')
            success = True  # Setting Success to True
        except smtplib.SMTPAuthenticationError:   # If Login Failed
            print('Wrong Company Password Entered!')
            # otp = None
            success = False
        except smtplib.SMTPNotSupportedError:   # If AUTH Command is not supported
            print('The AUTH command is not supported by the server.')
        except smtplib.SMTPException:           # If Login Failed
            print('No suitable authentication method was found.')
        except smtplib.SMTPHeloError:           # If Server didn't reply properly to HELO greeting
            print('The server didn\'t reply properly to the helo greeting.')
        except smtplib.SMTPRecipientsRefused:   # If Server rejected ALL recipients
            print('The server rejected ALL recipients (no mail was sent).')
        except smtplib.SMTPSenderRefused:       # If Server rejected the from_addr
            print('The server didn\'t accept the from_addr.')
        except smtplib.SMTPDataError:           # If Server replied with an unexpected error code (other than a refusal of a recipient)
            print('The server replied with an unexpected error code (other than a refusal of a recipient).')
        except smtplib.SMTPNotSupportedError:   # If Server does not support the SMTPUTF8 extension
            print('The mail_options parameter includes \'SMTPUTF8\' but the SMTPUTF8 extension is not supported by the server.')
        finally:
            con.quit()  # Quitting SMTP Connection
            print('Logged out of the Company Mail')
            print('Sending Process Ended')
            return success  # Returning Success
    else:   # If Password is None
        print('No Admin Password Given')
        return False

# Function to send OTP to the user
@app.route('/forgotpassword', methods=['GET','POST'])
def forgotpassword():
    message=None
    global logged_in
    global receiver
    if request.method == "POST":
        receiver = request.form.get('receiver')   # Getting Receiver's Email from Form
        with open('E:\Fraud Detection Documents\EMAIL_PASS.pwd', 'r') as f:
            comp_pass = f.read()    # Getting Company Password
        print("Mail Receiver : ",receiver)
        
        if send_mail(comp_pass):    # If Sending Mail is Successful
            print(f'Mail Sent to Receiver {receiver} with OTP : {otp}')
            return redirect('/OTPVerification') # Redirecting to OTP Verification Page
        else:   # If Sending Mail is Unsuccessful
            message = 'Sender\'s Password is Wrong!'    # Setting Message

    print(f"Logged In : {logged_in}")
    return render_template('forgotpassword.html', title='Forgot Password', message=message)

# Function to verify OTP
@app.route('/OTPVerification', methods=['GET','POST'])
def otpverification():
    if request.method == "POST":
        verify = request.form.get('otp')    # Getting OTP from Form
        if verify == otp:   # If OTP is correct
            print('OTP Matched!')
            return redirect('/ChangePassword')  # Redirecting to Change Password Page
        else:
            print('Wrong OTP Entered!')
    return render_template('otpverification.html', title='OTP Verification', otp=otp)

# Function to change password
@app.route('/ChangePassword', methods=['GET','POST'])
def changepassword():
    global loginmsg
    global adminpass
    if request.method == "POST":
        np = request.form.get('newpass')    # Getting New Password from Form
        cp = request.form.get('confpass')   # Getting Confirm Password from Form
        print('New Password : ',np)
        print('Confirm Password : ',cp)
        if np == cp:    # If New Password and Confirm Password Matched
            print('New Pasword Matched!')
            print('Receiver Data whose Password is to be changed : ',receiver)
            with open(r'pwd.pwd', 'w') as f:    # Writing New Password to File
                f.write(np)     # Writing New Password to File  
                adminpass = np  # Setting Admin Password to New Password
            with open('E:\Fraud Detection Documents\EMAIL_PASS.pwd', 'r') as f:   # Reading Company Password from File
                comp_pass = f.read()    # Reading Company Password from File
            print(f'Password Changed Successfully! for user {receiver}\n')
            if send_confirmation(comp_pass):    # Sending Confirmation Mail to User
                print('Confirmation Mail Sent to User!')
            global pschanged
            pschanged = True    # Setting Password Changed to True
            loginmsg = 'Password Changed Successfully. You can login to your account now.'  # Setting Login Message
            return redirect('/login')
        else:   # If New Password and Confirm Password didn't Match
            print('New Password did not match! Re-Enter Passwords.')
    return render_template('changepassword.html', title='Change Password')

@app.route('/logout')
def logout():
    global logged_in
    logged_in = False   # Setting Logged In to False
    global alert
    alert = None    # Setting Alert to None
    global loginmsg
    loginmsg = None    # Setting Login Message to None
    print(f"Logged in : {logged_in}")
    return redirect('/login')   # Redirecting to Login Page

# Function to Handle Dashboard Functionalities
@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    global loginmsg
    loginmsg = None
    global alert
    global data
    flag = 0    # Flag to check if transaction data is entered
    opensearch = False  # Flag to check if search is open
    result = df = load_data()   # Loading Data
    # result = pd.DataFrame()   # Initializing Result
    fig = None  # Initializing Figure
    if request.method == 'POST':
        # Get data from Transaction Entry Form
        trans_type=request.form.get('trans_type')
        trans_amt=request.form.get('trans_amt')
        trans_nameOrig=request.form.get('trans_nameOrig')
        trans_oldbalanceOrig=request.form.get('trans_oldbalanceOrg')
        trans_newbalanceOrig=request.form.get('trans_newbalanceOrig')
        trans_nameDest=request.form.get('trans_nameDest')
        trans_oldbalanceDest=request.form.get('trans_oldbalanceDest')
        trans_newbalanceDest=request.form.get('trans_newbalanceDest')

        # Get Data From Reports Section
        searchSelect = request.form.get('searchSelect')
        typeSelect = request.form.get('typeSelect')
        predSelect = request.form.get('predSelect')
        sdate = request.form.get('sdate')
        edate = request.form.get('edate')
        print(f"Search Option Selected : {searchSelect}\nType Option Selected : {typeSelect}\nPrediction Option Selected : {predSelect}\nStart Date : {sdate}\nEnd Date : {edate}")
        

        if searchSelect != None and searchSelect != '':   # If Search Option is Selected
            print("Search Details Entered!")
            opensearch = True   # Setting Open Search to True
            if searchSelect == 'Transaction_Type':  # If Search Option is Transaction Type
                print('Transaction Type Selected!')
                if typeSelect != None and typeSelect != '':  # If Transaction Type is Selected
                    print('Transaction Type : ' + typeSelect)
                    result = df.query("Transaction_Type == @typeSelect")    # Getting Data for Selected Transaction Type
                    print('Result is :')
                    print(result)
                    prediction_counts = result['Prediction'].value_counts().reset_index()   # Getting Number of each Predications for Selected Transaction Type
                    print('Prediction Counts :')
                    print(prediction_counts)
                    fig2 = px.bar(prediction_counts, x='Prediction', y='count')  # Plotting Bar Graph for Number of each Predications for Selected Transaction Type
                    fig2.update_layout(xaxis_title='Prediction', yaxis_title='Number of Transactions',title=f'Number of Transactions per Prediction for {typeSelect} Transactions')   # Setting Title and Axis Labels
                    fig = fig2.to_html()    # Converting Figure to HTML
                    print('Figure present : ' + str(fig != None))
                else:   # If Transaction Type is not Selected
                    print('No Transaction Type Selected!')
                    result = df  # Getting All Data
                    fig = px.sunburst(df, path=['Transaction_Type', 'Prediction'], values='Transaction_Amount').to_html()   # Plotting Sunburst Graph for All Data and Converting to HTML
            elif searchSelect == 'Prediction':  # If Search Option is Prediction
                print('Prediction Selected!')
                if predSelect != None and predSelect != '':   # If Prediction is Selected
                    print('Prediction : ' + predSelect)
                    result = df.query("Prediction == @predSelect")  # Getting Data for Selected Prediction
                    transaction_type_counts = result.value_counts().reset_index()   # Getting Number of each Transaction Type for Selected Prediction
                    fig2 = px.pie(transaction_type_counts, values='count', names='Transaction_Type')    # Plotting Pie Chart for Number of each Transaction Type for Selected Prediction
                    fig2.update_layout(title=f'TransactionType Distribution for {predSelect} Predictions')  # Setting Title
                    fig = fig2.to_html()    # Converting Figure to HTML
                else:   # If Prediction is not Selected
                    print('No Prediction Selected!')
                    result = df # Getting All Data
                    # Calculate the counts for Fraud and Not Fraud predictions per Transaction_Type
                    grouped_df = df.groupby(['Transaction_Type', 'Prediction']).size().reset_index(name='Count')    # Grouping Data by Transaction Type and Prediction
                    # Filter the DataFrame for Fraud and Not Fraud predictions
                    fraud_df = grouped_df[grouped_df['Prediction'] == 'Fraud']
                    not_fraud_df = grouped_df[grouped_df['Prediction'] == 'Not Fraud']
                    # Create the double bar plot using Plotly
                    fig2 = go.Figure(data=[
                        go.Bar(name='Fraud', x=fraud_df['Transaction_Type'], y=fraud_df['Count']),
                        go.Bar(name='Not Fraud', x=not_fraud_df['Transaction_Type'], y=not_fraud_df['Count'])
                    ])
                    # Update the layout of the plot
                    fig2.update_layout(barmode='group', xaxis_title='Transaction_Type', yaxis_title='Count',
                                    title='Number of Predicted Transactions per Transaction Type')  # Setting Title and Axis Labels
                    fig = fig2.to_html()    # Converting Figure to HTML
            elif searchSelect == 'Date':    # If Search Option is Date
                print('Date Selected!')
                if sdate != None and sdate != '' and edate != None and edate != '':  # If Start Date and End Date are Selected
                    print(f"Start Date : {sdate}\nEnd Date : {edate}")
                    sdate = datetime.strptime(sdate, "%Y-%m-%d").date().strftime("%d-%m-%Y")    # Converting Start Date to Correct Format
                    edate = datetime.strptime(edate, "%Y-%m-%d").date().strftime("%d-%m-%Y")    # Converting End Date to Correct Format
                    print(f"New Start Date : {sdate}\nNew End Date : {edate}")
                    result = df.query("@sdate <= Date <= @edate")   # Getting Data for Selected Date Range
                    # Calculate the prediction counts
                    prediction_counts = result['Prediction'].value_counts().reset_index()
                    # Create the bar plot using Plotly Express
                    fig2 = px.bar(prediction_counts, x='Prediction', y='count')
                    # Update the chart title and axis labels
                    fig2.update_layout(title=f'Prediction Distribution between {sdate} and {edate}',
                                    xaxis_title='Prediction', yaxis_title='Count')
                    fig = fig2.to_html()    # Converting Figure to HTML
                else:   # If Start Date and End Date are not Selected
                    print('No Date Selected!')
                    result = df # Getting All Data
                    prediction_counts = result['Prediction'].value_counts().reset_index()   # Getting Number of each Predications for All Data
                    # Create the pie chart using Plotly Express
                    fig2 = px.pie(prediction_counts, values='count', names='Prediction')
                    # Update the chart title
                    fig2.update_layout(title=f'All Time Prediction Distribution')
                    fig = fig2.to_html()    # Converting Figure to HTML
            else:   # If Search Option is not Selected
                print('No Search Option Selected!')
                result = df # Getting All Data
        
        elif trans_type!=None and trans_type!='':   # If Data Entry Form is Selected instead of Search Option
            # Creting dictionary for extracted data
            print("Transaction Details Entered!")
            
            # Creating dictionary for extracted data
            data = {'type': trans_type,
                    'amount': trans_amt,
                    'srcacc': trans_nameOrig,
                    'srcold': trans_oldbalanceOrig,
                    'srcnew': trans_newbalanceOrig,
                    'destacc': trans_nameDest,
                    'destold': trans_oldbalanceDest,
                    'destnew': trans_newbalanceDest,
                    'date': datetime.strftime(datetime.now(), '%d-%m-%Y'),
                    'time': datetime.strftime(datetime.now(), '%H:%M:%S'),
                    'isFraud': 0
                    }
        
            # Checking if all the fields are filled
            if trans_type and trans_amt and trans_nameOrig and trans_oldbalanceOrig and trans_newbalanceOrig and trans_nameDest and trans_oldbalanceDest and trans_newbalanceDest:
                # Creating DataFrame from the dictionary
                tdata = pd.DataFrame({'step': [1],
                        'type': [trans_type],
                        'amount': [trans_amt],
                        'name_orig': [trans_nameOrig],
                        'oldbalanceOrg': [trans_oldbalanceOrig],
                        'newbalanceOrig': [trans_newbalanceOrig],
                        'name_dest': [trans_nameDest],
                        'oldbalanceDest': [trans_oldbalanceDest],
                        'newbalanceDest': [trans_newbalanceDest],
                        })
                print(f'DataFrame => {tdata}')
                model_path = r'models\v3\ann_fraud_detection.h5'    # Path to the model
                pp_path = r'models\v3\ann_fraud_detection_preprocessor.jb'  # Path to the preprocessor
                out = predict(model_path, pp_path, tdata)   # Calling the predict function
                print(out[0][0] > 0.5)  # Printing the output
                if out[0][0] > 0.5:     # Checking if the output is greater than 0.5
                    print('Fraud')
                    data['isFraud'] = 1
                    isFraud = 'Fraud'
                else:                   # If the output is less than 0.5
                    print('Not Fraud')
                    data['isFraud'] = 0
                    isFraud = 'Not Fraud'
                flag = 1    # Setting the flag to check if transaction data is entered
                print('flag changed to : ', flag)
                db = getdb()    # Getting the database
                db.add(Transaction(Transaction_Type=trans_type, 
                                Transaction_Amount=trans_amt, 
                                Source_Account=trans_nameOrig, 
                                SA_Old_Balance=trans_oldbalanceOrig, 
                                SA_New_Balance=trans_newbalanceOrig, 
                                Destination_Account=trans_nameDest, 
                                DA_Old_Balance=trans_oldbalanceDest, 
                                DA_New_Balance=trans_newbalanceDest, 
                                Date=datetime.strftime(datetime.now(), '%d-%m-%Y'),
                                Time=datetime.strftime(datetime.now(), '%H:%M:%S'),
                                Prediction=isFraud))    # Adding the data to the database
                db.commit()     # Commiting the changes
                db.close()      # Closing the database
                print('Data Saved Successfully')
                alert = 'success'   # Setting the alert type
                loginmsg = 'Data Saved Successfully!'   # Setting the alert message
            else:   # If all the fields are not filled
                print('Data Not Saved')
                alert = 'danger'    # Setting the alert type
                loginmsg = 'Data Not Saved!'    # Setting the alert message

        print('The Dataset for Search is :')
        print(result)
        print('Database : ')
        print(df)
        # if not result.empty:
        #     result = result.to_html()   # Converting the result to HTML
        # if not df.empty:
        #     df = df.to_html()   # Converting the DataFrame to HTML
        # return render_template('dashboard.html', title='Dashboard', logged_in=logged_in, message = loginmsg, alert=alert, df = df.to_html(), data=data, flag=flag, result=result.to_html(), fig=fig, osr = opensearch)
    # GET Request
    print(f"Logged In : {logged_in}")
    print(f"Data : {data}")
    return render_template('dashboard.html', title='Dashboard', logged_in=logged_in, message = loginmsg, alert=alert, df = df.to_html(), data=data, flag=flag, result=result.to_html(), fig=fig, osr = opensearch)

# Route for the Homepage
@app.route('/homepage')
def homepage():
    return render_template('homepage.html', title="Home", logged_in=logged_in, message = loginmsg, alert=alert)

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=8000, debug=True)
    app.run(host='127.0.0.1', port=8000, debug=True)    # Running the Flask App
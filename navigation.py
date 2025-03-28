# import streamlit as st

# import base64
# import numpy as np
# import matplotlib.pyplot as plt 
# from tkinter.filedialog import askopenfilename

# import streamlit as st

# import matplotlib.image as mpimg

# import streamlit as st
# import base64

# import pandas as pd
# import sqlite3

# # ================ Background image ===

# def add_bg_from_local(image_file):
#     with open(image_file, "rb") as image_file:
#         encoded_string = base64.b64encode(image_file.read())
#     st.markdown(
#     f"""
#     <style>
#     .stApp {{
#         background-image: url(data:image/{"png"};base64,{encoded_string.decode()});
#         background-size: cover
#     }}
#     </style>
#     """,
#     unsafe_allow_html=True
#     )
# add_bg_from_local('1.jpg')


# def navigation():
#     try:
#         path = st.experimental_get_query_params()['p'][0]
#     except Exception as e:
#         st.error('Please use the main app.')
#         return None
#     return path





# if navigation() == "home":
#     st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)
    
#     print()
#     print()

#     print()

#     st.text("                 ")
#     st.text("                 ")
#     a = "  * Hybrid cryptography for secured file storage in the cloud combines the strengths of symmetric encryption (for fast data encryption) and asymmetric encryption (for secure key management). In this approach, the file is encrypted using a symmetric algorithm like AES, while the AES key itself is encrypted with the recipient's public key using asymmetric encryption. This ensures both data confidentiality and efficient key distribution, making it ideal for secure cloud storage. * "

    
#     st.markdown(f'<h1 style="color:#000000;text-align: justify;font-size:24px;font-family:Caveat, sans-serif;">{a}</h1>', unsafe_allow_html=True)

#     st.text("                 ")
#     st.text("                 ")
    
#     st.text("                 ")
#     st.text("                 ")
    


# elif navigation()=='reg':
   
#     st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)

#     st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Register Here !!!"}</h1>', unsafe_allow_html=True)
    
#     import streamlit as st
#     import sqlite3
#     import re
    
#     # Function to create a database connection
#     def create_connection(db_file):
#         conn = None
#         try:
#             conn = sqlite3.connect(db_file)
#         except sqlite3.Error as e:
#             print(e)
#         return conn
    
#     # Function to create a new user
#     def create_user(conn, user):
#         sql = ''' INSERT INTO users(name, password, email, phone)
#                   VALUES(?,?,?,?) '''
#         cur = conn.cursor()
#         cur.execute(sql, user)
#         conn.commit()
#         return cur.lastrowid
    
#     # Function to check if a user already exists
#     def user_exists(conn, email):
#         cur = conn.cursor()
#         cur.execute("SELECT * FROM users WHERE email=?", (email,))
#         if cur.fetchone():
#             return True
#         return False
    
#     # Function to validate email
#     def validate_email(email):
#         pattern = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
#         return re.match(pattern, email)
    
#     # Function to validate phone number
#     def validate_phone(phone):
#         pattern = r'^[6-9]\d{9}$'
#         return re.match(pattern, phone)
    
#     # Main function
#     def main():
#         # st.title("User Registration")
    
#         # Create a database connection
#         conn = create_connection("dbs.db")
    
#         if conn is not None:
#             # Create users table if it doesn't exist
#             conn.execute('''CREATE TABLE IF NOT EXISTS users
#                          (id INTEGER PRIMARY KEY,
#                          name TEXT NOT NULL,
#                          password TEXT NOT NULL,
#                          email TEXT NOT NULL UNIQUE,
#                          phone TEXT NOT NULL);''')
    
#             # User input fields
#             name = st.text_input("Enter your name")
#             password = st.text_input("Enter your password", type="password")
#             confirm_password = st.text_input("Confirm your password", type="password")
#             email = st.text_input("Enter your email")
#             phone = st.text_input("Enter your phone number")
    
#             col1, col2 = st.columns(2)

#             with col1:
                    
#                 aa = st.button("REGISTER")
                
#                 if aa:
                    
#                     if password == confirm_password:
#                         if not user_exists(conn, email):
#                             if validate_email(email) and validate_phone(phone):
#                                 user = (name, password, email, phone)
#                                 create_user(conn, user)
#                                 st.success("User registered successfully!")
#                             else:
#                                 st.error("Invalid email or phone number!")
#                         else:
#                             st.error("User with this email already exists!")
#                     else:
#                         st.error("Passwords do not match!")
                    
#                     conn.close()
#                     # st.success('Successfully Registered !!!')
#                 # else:
                    
#                     # st.write('Registeration Failed !!!')     
            
#             with col2:
                    
#                 aa = st.button("LOGIN")
                
#                 if aa:
#                     import subprocess
#                     subprocess.run(['python','-m','streamlit','run','login.py'])
#                     # st.success('Successfully Registered !!!')
    
    
    
  
#     if __name__ == '__main__':
#         main()



# elif navigation()=='Login':
    
#     st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)


#     # Function to create a database connection
#     def create_connection(db_file):
#         conn = None
#         try:
#             conn = sqlite3.connect(db_file)
#         except sqlite3.Error as e:
#             print(e)
#         return conn
    
#     # Function to create a new user
#     def create_user(conn, user):
#         sql = ''' INSERT INTO users(name, password, email, phone)
#                   VALUES(?,?,?,?) '''
#         cur = conn.cursor()
#         cur.execute(sql, user)
#         conn.commit()
#         return cur.lastrowid
    
#     # Function to validate user credentials
#     def validate_user(conn, name, password):
#         cur = conn.cursor()
#         cur.execute("SELECT * FROM users WHERE name=? AND password=?", (name, password))
#         user = cur.fetchone()
#         if user:
#             return True, user[1]  # Return True and user name
#         return False, None
    
#     # Main function
#     def main():
#         # st.title("User Login")
#         st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:24px;">{"Login here"}</h1>', unsafe_allow_html=True)
    
    
#         # Create a database connection
#         conn = create_connection("dbs.db")
    
#         if conn is not None:
#             # Create users table if it doesn't exist
#             conn.execute('''CREATE TABLE IF NOT EXISTS users
#                          (id INTEGER PRIMARY KEY,
#                          name TEXT NOT NULL,
#                          password TEXT NOT NULL,
#                          email TEXT NOT NULL UNIQUE,
#                          phone TEXT NOT NULL);''')
    
#             st.write("Enter your credentials to login:")
#             name = st.text_input("User name")
#             password = st.text_input("Password", type="password")
    
#             col1, col2 = st.columns(2)
    
#             with col1:
                    
#                 aa = st.button("Login")
                
#                 if aa:
    
    
#             # # if st.button("Login"):
#                     is_valid, user_name = validate_user(conn, name, password)
#                     if is_valid:
#                         st.success(f"Welcome back, {user_name}! Login successful!")
                        
#                         import subprocess
#                         subprocess.run(['python','-m','streamlit','run','app.py'])
                       
                        
#                     else:
#                         st.error("Invalid user name or password!")
                        
    
    
#             # Close the database connection
#             conn.close()
#         else:
#             st.error("Error! cannot create the database connection.")
    
#     if __name__ == '__main__':
#         main()



# elif navigation()=='admin':
    
#         st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Shadow Net"}</h1>', unsafe_allow_html=True)

#         st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:24px;">{"Admin Login here!!!"}</h1>', unsafe_allow_html=True)

#         aname = st.text_input("User name")
#         apassword = st.text_input("Password", type="password")
    
#         col1, col2, col3 = st.columns(3)
    
#         with col2:
                
#             aa = st.button("Login")
            
#             if aa:
                
#                 if aname=="Admin" and apassword=="12345":
                    
                
#                      st.success(f"Login successful!")
#                      import subprocess
#                      subprocess.run(['python','-m','streamlit','run','Admin.py'])
#                 else:
                    
#                      st.warning(f"Invalid Username")

    


# elif navigation()=='dash':    
    
#     st.image("network_traffic_zigzag.gif")
    
    
# elif navigation()=='dashb':    
    
#     import os
#     # Read the HTML file
#     html_file_path = "templates/dash.html"
    
#     # Make sure the HTML file exists
#     if os.path.exists(html_file_path):
#         with open(html_file_path, 'r') as file:
#             html_content = file.read()
    
#         # Display the HTML content
#         st.components.v1.html(html_content, height=600)
#     else:
#         st.error("HTML file not found.")
    
    
    
    



# elif navigation()=='pdff':    
    
#     pdf_output = "Cloud/Report.pdf"
#     # Provide the download button for the user
#     with open(pdf_output, "rb") as pdf_file:
#         st.download_button(
#             label="Download PDF Report",
#             data=pdf_file,
#             file_name="Report.pdf",
#             mime="application/pdf"
#         )    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

import streamlit as st
import base64
import numpy as np
import matplotlib.pyplot as plt
import sqlite3
import re
import subprocess
import os

# ================ Background image ===
def add_bg_from_local(image_file):
    with open(image_file, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url(data:image/{"png"};base64,{encoded_string.decode()});
            background-size: cover
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
add_bg_from_local('1.jpg')

def navigation():
    try:
        path = st.experimental_get_query_params()['p'][0]
    except Exception as e:
        st.error('Please use the main app.')
        return None
    return path

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except sqlite3.Error as e:
        print(e)
    return conn

def create_user(conn, user):
    sql = ''' INSERT INTO users(name, password, email, phone)
              VALUES(?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, user)
    conn.commit()
    return cur.lastrowid

def user_exists(conn, email):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    if cur.fetchone():
        return True
    return False

def validate_email(email):
    pattern = r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'
    return re.match(pattern, email)

def validate_phone(phone):
    pattern = r'^[6-9]\d{9}$'
    return re.match(pattern, phone)

def validate_user(conn, name, password):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name=? AND password=?", (name, password))
    user = cur.fetchone()
    if user:
        return True, user[1]  # Return True and user name
    return False, None

if navigation() == "home":
    st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)
    st.text("                 ")
    a = "  * Hybrid cryptography for secured file storage in the cloud combines the strengths of symmetric encryption (for fast data encryption) and asymmetric encryption (for secure key management). In this approach, the file is encrypted using a symmetric algorithm like AES, while the AES key itself is encrypted with the recipient's public key using asymmetric encryption. This ensures both data confidentiality and efficient key distribution, making it ideal for secure cloud storage. * "
    st.markdown(f'<h1 style="color:#000000;text-align: justify;font-size:24px;font-family:Caveat, sans-serif;">{a}</h1>', unsafe_allow_html=True)

elif navigation() == 'reg':
    st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Register Here !!!"}</h1>', unsafe_allow_html=True)

    conn = create_connection("dbs.db")
    if conn is not None:
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     password TEXT NOT NULL,
                     email TEXT NOT NULL UNIQUE,
                     phone TEXT NOT NULL);''')

        name = st.text_input("Enter your name")
        password = st.text_input("Enter your password", type="password")
        confirm_password = st.text_input("Confirm your password", type="password")
        email = st.text_input("Enter your email")
        phone = st.text_input("Enter your phone number")

        if st.button("REGISTER"):
            if password == confirm_password:
                if not user_exists(conn, email):
                    if validate_email(email) and validate_phone(phone):
                        user = (name, password, email, phone)
                        create_user(conn, user)
                        st.success("User registered successfully!")
                    else:
                        st.error("Invalid email or phone number!")
                else:
                    st.error("User with this email already exists!")
            else:
                st.error("Passwords do not match!")
            conn.close()

        if st.button("LOGIN"):
            subprocess.run(['python', '-m', 'streamlit', 'run', 'navigation.py?p=Login'])

elif navigation() == 'Login':
    st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:24px;">{"Login here"}</h1>', unsafe_allow_html=True)

    conn = create_connection("dbs.db")
    if conn is not None:
        conn.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     password TEXT NOT NULL,
                     email TEXT NOT NULL UNIQUE,
                     phone TEXT NOT NULL);''')

        st.write("Enter your credentials to login:")
        name = st.text_input("User name")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            is_valid, user_name = validate_user(conn, name, password)
            if is_valid:
                st.success(f"Welcome back, {user_name}! Login successful!")
                subprocess.run(['python', '-m', 'streamlit', 'run', 'app.py'])
            else:
                st.error("Invalid user name or password!")
        conn.close()

elif navigation() == 'admin':
    st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Shadow Net"}</h1>', unsafe_allow_html=True)
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:24px;">{"Admin Login here!!!"}</h1>', unsafe_allow_html=True)

    aname = st.text_input("User name")
    apassword = st.text_input("Password", type="password")

    if st.button("Login"):
        if aname == "Admin" and apassword == "12345":
            st.success(f"Login successful!")
            subprocess.run(['python', '-m', 'streamlit', 'run', 'Admin.py'])
        else:
            st.warning(f"Invalid Username")

elif navigation() == 'dash':
    st.image("network_traffic_zigzag.gif")

elif navigation() == 'dashb':
    html_file_path = "templates/dash.html"
    if os.path.exists(html_file_path):
        with open(html_file_path, 'r') as file:
            html_content = file.read()
        st.components.v1.html(html_content, height=600)
    else:
        st.error("HTML file not found.")

elif navigation() == 'pdff':
    pdf_output = "Cloud/Report.pdf"
    with open(pdf_output, "rb") as pdf_file:
        st.download_button(
            label="Download PDF Report",
            data=pdf_file,
            file_name="Report.pdf",
            mime="application/pdf"
        )
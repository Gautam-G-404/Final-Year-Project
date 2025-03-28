import streamlit as st
import pandas as pd


import streamlit as st
import base64
import sqlite3
from streamlit_option_menu import option_menu


# ================ Background image ===


st.markdown(f'<h1 style="color:#8d1b92;text-align: center;font-size:36px;">{"Secured file storage using hybrid cryptography in Cloud"}</h1>', unsafe_allow_html=True)



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


# st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:22px;">{"Cryptography!!!"}</h1>', unsafe_allow_html=True)




selected = option_menu(
    menu_title=None, 
    options=["PDF","DOC","TEXT","IMAGE","VIDEO","AUDIO"],  
    orientation="horizontal",
)


st.markdown(
    """
    <style>
    .option_menu_container {
        position: fixed;
        top: 20px;
        right: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


if selected == "PDF":
    
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"PDF File Encryption!!!"}</h1>', unsafe_allow_html=True)

            
    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import os
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    
    # Upload PDF file
    uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])
    
    if uploaded_file is not None:
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
                
            action = st.radio("Action", ("Encrypt", "Decrypt"))
    
            # Encrypt button
            if action=="Encrypt":
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_file.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_file.bin",
                    mime="application/octet-stream",
                )
    
            # Decrypt button
            if action=="Decrypt":
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_file.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_file.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file
                decrypted_file_path = "decrypted_file.pdf"
                with open(decrypted_file_path, "wb") as f:
                    f.write(decrypted_data)
                st.success(f"File decrypted and saved as {decrypted_file_path}")
    
                # Download decrypted file
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name="decrypted_file.pdf",
                    mime="application/pdf",
                )
                
                
if selected=="TEXT":
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Text File Encryption!!!"}</h1>', unsafe_allow_html=True)

        
    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import os
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    # Streamlit app
    # st.title("Text File Encryption and Decryption using AES")
    
    # Upload text file
    uploaded_file = st.file_uploader("Upload a text file", type=["txt"])
    
    if uploaded_file is not None:
        # Display file details
        file_details = {
            "Filename": uploaded_file.name,
            "File Type": uploaded_file.type,
            "File Size": uploaded_file.size,
        }
        st.write(file_details)
    
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
                
            action = st.radio("Action", ("Encrypt", "Decrypt"))

            if action=="Encrypt":
                
            # Encrypt button
            # if st.button("Encrypt"):
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_file.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_file.bin",
                    mime="application/octet-stream",
                )
            
    
            # Encrypt button
            if action=="Decrypt":
    
            # Decrypt button
            # if st.button("Decrypt"):
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_file.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_file.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file
                decrypted_file_path = "decrypted_file.txt"
                with open(decrypted_file_path, "wb") as f:
                    f.write(decrypted_data)
                st.success(f"File decrypted and saved as {decrypted_file_path}")
    
                # Download decrypted file
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name="decrypted_file.txt",
                    mime="text/plain",
                )
                        
                    
if selected=="DOC":
        
    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import os
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    # Streamlit app
    # st.title("File Encryption and Decryption using AES")
    
    # Upload document
    uploaded_file = st.file_uploader("Upload a file", type=["doc", "docx", "ppt", "pptx", "csv", "xlsx"])
    
    if uploaded_file is not None:
        # Display file details
        file_details = {
            "Filename": uploaded_file.name,
            "File Type": uploaded_file.type,
            "File Size": uploaded_file.size,
        }
        st.write(file_details)
    
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
    
            action = st.radio("Action", ("Encrypt", "Decrypt"))
    
            if action == "Encrypt":
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_file.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_file.bin",
                    mime="application/octet-stream",
                )
    
            if action == "Decrypt":
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_file.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_file.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file with correct extension based on MIME type
                if uploaded_file.type == "application/msword":
                    decrypted_file_path = "decrypted_file.doc"
                elif uploaded_file.type == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                    decrypted_file_path = "decrypted_file.docx"
                elif uploaded_file.type == "application/vnd.ms-powerpoint":
                    decrypted_file_path = "decrypted_file.ppt"
                elif uploaded_file.type == "application/vnd.openxmlformats-officedocument.presentationml.presentation":
                    decrypted_file_path = "decrypted_file.pptx"
                elif uploaded_file.type == "text/csv":
                    decrypted_file_path = "decrypted_file.csv"
                elif uploaded_file.type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
                    decrypted_file_path = "decrypted_file.xlsx"
                else:
                    decrypted_file_path = "decrypted_file.bin"
    
                with open(decrypted_file_path, "wb") as f:
                    f.write(decrypted_data)
                st.success(f"File decrypted and saved as {decrypted_file_path}")
    
                # Download decrypted file
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=decrypted_file_path,
                    mime=uploaded_file.type,
                )

                    
                    
if selected=="IMAGE":     

    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Image Encryption!!!"}</h1>', unsafe_allow_html=True)

    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import os
    from PIL import Image
    import io
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    # Streamlit app
    # st.title("Image Encryption and Decryption using AES")
    
    # Upload image file
    uploaded_file = st.file_uploader("Upload an Image file", type=["png", "jpg", "jpeg"])
    
    if uploaded_file is not None:
        # Display file details
        file_details = {
            "Filename": uploaded_file.name,
            "File Type": uploaded_file.type,
            "File Size": uploaded_file.size,
        }
        st.write(file_details)
    
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
                
            action = st.radio("Action", ("Encrypt", "Decrypt"))

    
            # Encrypt button
            if action=="Encrypt":
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_image.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_image.bin",
                    mime="application/octet-stream",
                )
    

            if action=="Decrypt":
                
                
            # Decrypt button
            # if st.button("Decrypt"):
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_image.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_image.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file as an image
                decrypted_image_path = "decrypted_image.png"  # You can change the format if needed
    
                # Write decrypted image
                with open(decrypted_image_path, "wb") as f:
                    f.write(decrypted_data)
    
                st.success(f"File decrypted and saved as {decrypted_image_path}")
    
                # Display decrypted image in the app
                decrypted_image = Image.open(io.BytesIO(decrypted_data))
                st.image(decrypted_image, caption="Decrypted Image")
    
                # Download decrypted file
                st.download_button(
                    label="Download Decrypted Image",
                    data=decrypted_data,
                    file_name=decrypted_image_path,
                    mime="image/png",  # Adjust MIME type based on file extension
                )
    
    
      
if selected=="AUDIO":       

    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Audio Encryption!!!"}</h1>', unsafe_allow_html=True)

    
    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    import os
    import io
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    # Streamlit app
    # st.title("Audio File Encryption and Decryption using AES")
    
    # Upload audio file
    uploaded_file = st.file_uploader("Upload an Audio file", type=["mp3", "wav"])
    
    if uploaded_file is not None:
        # Display file details
        file_details = {
            "Filename": uploaded_file.name,
            "File Type": uploaded_file.type,
            "File Size": uploaded_file.size,
        }
        st.write(file_details)
    
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
            
            action = st.radio("Action", ("Encrypt", "Decrypt"))

            if action=="Encrypt":
    
            # Encrypt button
            # if st.button("Encrypt"):
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_audio.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_audio.bin",
                    mime="application/octet-stream",
                )
    
            # Decrypt button
            if action=="Decrypt":
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_audio.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_audio.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file as audio
                decrypted_audio_path = "decrypted_audio.mp3"  # Adjust the format if necessary
    
                # Write decrypted audio file
                with open(decrypted_audio_path, "wb") as f:
                    f.write(decrypted_data)
    
                st.success(f"File decrypted and saved as {decrypted_audio_path}")
    
                # Provide download button for decrypted audio
                st.download_button(
                    label="Download Decrypted Audio",
                    data=decrypted_data,
                    file_name=decrypted_audio_path,
                    mime="audio/mpeg" if uploaded_file.type == "audio/mpeg" else "audio/wav",  # Adjust MIME type for MP3/WAV
                )
    

                
if selected=="VIDEO":               
    
    st.markdown(f'<h1 style="color:#000000;text-align: center;font-size:20px;">{"Video Encryption!!!"}</h1>', unsafe_allow_html=True)

    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    import os
    
    # Function to encrypt a file using AES
    def encrypt_file(input_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(input_file.read(), AES.block_size)
        encrypted_data = cipher.iv + cipher.encrypt(padded_data)
        return encrypted_data
    
    # Function to decrypt a file using AES
    def decrypt_file(encrypted_data, key):
        iv = encrypted_data[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data
    
    # Streamlit app
    # st.title("Video File Encryption and Decryption using AES")
    
    # Upload video file
    uploaded_file = st.file_uploader("Upload a Video file", type=["mp4", "avi", "mov", "mkv"])
    
    if uploaded_file is not None:
        # Display file details
        file_details = {
            "Filename": uploaded_file.name,
            "File Type": uploaded_file.type,
            "File Size": uploaded_file.size,
        }
        st.write(file_details)
    
        # Enter encryption key
        key = st.text_input("Enter a 16, 24, or 32-byte key (in hexadecimal or plain text):")
    
        if key:
            # Convert key to bytes
            if len(key) in [16, 24, 32]:
                key = key.encode()  # Use as plain text key
            else:
                try:
                    key = bytes.fromhex(key)  # Convert hex to bytes
                except ValueError:
                    st.error("Invalid key format. Please enter a valid 16, 24, or 32-byte key.")
                    st.stop()
    
            if len(key) not in [16, 24, 32]:
                st.error("Key must be 16, 24, or 32 bytes long.")
                st.stop()
            
            action = st.radio("Action", ("Encrypt", "Decrypt"))
            # Encrypt button
            if action=="Encrypt":
                st.write("Encrypting the file...")
                encrypted_data = encrypt_file(uploaded_file, key)
    
                # Save encrypted file
                encrypted_file_path = "encrypted_video.bin"
                with open(encrypted_file_path, "wb") as f:
                    f.write(encrypted_data)
                st.success(f"File encrypted and saved as {encrypted_file_path}")
    
                # Download encrypted file
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_video.bin",
                    mime="application/octet-stream",
                )
    
            # Decrypt button
            if action=="Decrypt":
                # Check if the encrypted file exists
                if not os.path.exists("encrypted_video.bin"):
                    st.error("No encrypted file found. Please encrypt the file first.")
                    st.stop()
    
                st.write("Decrypting the file...")
                with open("encrypted_video.bin", "rb") as f:
                    encrypted_data = f.read()
    
                decrypted_data = decrypt_file(encrypted_data, key)
    
                # Save decrypted file as video
                decrypted_video_path = "decrypted_video.mp4"  # Adjust format to .mp4 or .avi or others
    
                # Write decrypted video file
                with open(decrypted_video_path, "wb") as f:
                    f.write(decrypted_data)
    
                st.success(f"File decrypted and saved as {decrypted_video_path}")
    
                # Provide download button for decrypted video
                st.download_button(
                    label="Download Decrypted Video",
                    data=decrypted_data,
                    file_name=decrypted_video_path,
                    mime="video/mp4" if uploaded_file.type == "video/mp4" else "video/avi",  # Adjust MIME type for video formats
                )
                    
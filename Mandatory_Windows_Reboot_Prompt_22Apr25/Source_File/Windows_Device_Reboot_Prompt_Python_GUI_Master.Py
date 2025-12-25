'''
.Author       - Vishal Navgire
.Created on   - 03-April-2025
.Co-Author(s) - 
.Reviwer(s)   -  

.DESCRIPTION 
    Displays a GUI prompt on the user's screen if their Windows machine has not been restarted in the last 10 Days or more.

Pre-reqs:
N/A

Version Control:
03-April-2025 :: v1.0
'''


from PIL import Image
from PIL import ImageTk
import tkinter as tk
from tkinter import messagebox
import subprocess
import threading
import os
import socket

# Set up main window
Main_GUI = tk.Tk()
Main_GUI.title("𝗪𝗜𝗡𝗗𝗢𝗪𝗦 𝗗𝗘𝗩𝗜𝗖𝗘 𝗠𝗔𝗡𝗗𝗔𝗧𝗢𝗥𝗬 𝗦𝗖𝗛𝗘𝗗𝗨𝗟𝗘𝗗 𝗥𝗘𝗕𝗢𝗢𝗧 𝗔𝗟𝗘𝗥𝗧")
Main_GUI.geometry("650x450")
Main_GUI.configure(bg="Black", highlightbackground="Red", highlightthickness=5)  # Red border
Main_GUI.attributes("-topmost", True)
Main_GUI.resizable(False, False)

# Timer and limits
Time_Left = 60 * 60  # Countdown time in seconds (5 minutes)
Snooze_Count = 0
Snooze_Limit = 2
Final_Warning_Time = 15 * 60  # Final warning at 2 minutes

# Load and convert the Title logo image to a format tkinter can use
Title_Image_PIL  = Image.open(r"C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Restart_Logo.png")
Title_Image_Logo = ImageTk.PhotoImage(Title_Image_PIL)

# Set the window icon
Main_GUI.iconphoto(False, Title_Image_Logo)

# User and device info
Logged_In_Username = os.getlogin().upper()
Hostname = socket.gethostname()

# Display branding message
brand_message = tk.Label(
    Main_GUI,
    text=(f"Hi {Logged_In_Username}, you haven't rebooted your machine '{Hostname}' in the past 10 days. "
          "Please save your work, close all running applications and then click 'Reboot Now' for a safe device restart."),
    font=("Book Antiqua", 12),
    wraplength=500,
    fg="White",
    bg="Gray"
)                   
brand_message.pack(pady=10)

# Countdown label
Timer_Label = tk.Label(Main_GUI, text="", font=("Arial", 20), bg="Yellow", fg="Red")
Timer_Label.pack(pady=20)

# Restart Now button
Restart_Now_Button = tk.Button(Main_GUI, text="Restart Now", font=("Arial", 12), bg="Green", fg="White", width=15)
Restart_Now_Button.pack(pady=4)

# Restart Later button
Restart_Later_Button = tk.Button(Main_GUI, text="Restart Later", font=("Arial", 12), bg="Red", fg="White", width=15)
Restart_Later_Button.pack(pady=4)

Brand_Image = Image.open(r"C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Background_Logo.png")
Brand_Image = Brand_Image.resize((100, 100), Image.LANCZOS)  # Resize if needed
Brand_Image = ImageTk.PhotoImage(Brand_Image)

# Create a label to display the image and pack it below the 'Restart Later' button
Logo_Label       = tk.Label(Main_GUI, image=Brand_Image, bg="Black")
Logo_Label.image = Brand_Image  # Keep a reference to avoid garbage collection
Logo_Label.pack(pady=10)

# Disable window close
Main_GUI.protocol("WM_DELETE_WINDOW", lambda: None)

# Restore the window if it was minimized by an end user
def keep_on_top():
    Main_GUI.attributes("-topmost", True)
    Main_GUI.deiconify()  # Restores if minimized
    Main_GUI.after(1000, keep_on_top)  # Check every second

# Start the keep-on-top process
keep_on_top()

# Countdown update
def Update_Timer():
    global Time_Left, Snooze_Count
    if Time_Left > 0:
        hours, remainder = divmod(Time_Left, 3600)
        minutes, seconds = divmod(remainder, 60)
        Timer_Label.config(text=f"{hours:02} Hour/s : {minutes:02} Minutes : {seconds:02} Seconds Left Before Device '{Hostname}' Forced Rebooted.",
                           wraplength=500,
                           justify='center')

        # Disable snooze button (Restart Later Button) in final 2 minutes to prevent user from restarting device later.
        if Time_Left <= Final_Warning_Time:
            Restart_Later_Button.config(state="disabled")

        # Update countdown
        Time_Left -= 1
        Main_GUI.after(1000, Update_Timer)
    else:
        Perform_Reboot(force=True)

# Start the countdown timer
Main_GUI.after(1000, Update_Timer)

# Immediate reboot action
def Restart_Now_Action():
    Perform_Reboot(force=False)

# Restart Later action with limited snooze
def Restart_Later_Action():
    global Snooze_Count, Time_Left
    if Snooze_Count < Snooze_Limit:
        Snooze_Count += 1
        messagebox.showinfo("Device Restart Later", f"Device Restart Later attempt {Snooze_Count} of {Snooze_Limit}")
        Time_Left += 30 * 60  # Add 30 minutes
    else:
        messagebox.showwarning("Restart later Snooze Limit Reached !!!",
                               "No more snooze attempts are allowed. Please consider restarting your machine now.")
        Restart_Later_Button.config(state="disabled")

# Perform reboot in a separate thread to prevent GUI freeze
def Perform_Reboot(force=False):
    Reboot_Command = ["Powershell.Exe", "-Command", "Restart-Computer"]
    if force:
        Reboot_Command.append("-Force")
    threading.Thread(target=subprocess.run, args=(Reboot_Command,), kwargs={'check': True}).start()

# Set button commands
Restart_Now_Button.config(command=Restart_Now_Action)
Restart_Later_Button.config(command=Restart_Later_Action)

# Run the GUI
Main_GUI.mainloop()
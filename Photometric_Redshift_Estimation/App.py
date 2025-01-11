import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import pandas as pd
from astropy.io import fits  # For handling FITS files
import json
import bcrypt  # For password hashing


class RedshiftApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Photometric Redshift Estimation Tool")
        self.root.geometry("1200x800")

        # Load the background image
        self.background_image = Image.open("imgs/bg.png")
        self.background_photo = ImageTk.PhotoImage(self.background_image)

        # Create a Canvas for the background
        self.canvas = tk.Canvas(self.root, width=1200, height=800)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.create_image(0, 0, image=self.background_photo, anchor="nw")

        # Initialize user-related attributes
        self.users = self.load_users()  # Load users from JSON file
        self.current_user = None  # Define this before creating the navbar

        # Top Navigation Bar
        self.create_navbar()

        # Main Workspace
        self.create_workspace()

    def load_users(self):
        """Load user accounts from a JSON file."""
        try:
            with open("users.json", "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}  # Return an empty dictionary if file does not exist

    def save_users(self):
        """Save user accounts to a JSON file."""
        with open("users.json", "w") as file:
            json.dump(self.users, file)

    def create_navbar(self):
        # Navigation Bar Frame
        self.navbar = tk.Frame(self.root, bg="#333344", height=50)
        self.navbar.place(x=0, y=0, width=1200)

        # Profile Section
        self.profile_frame = tk.Frame(self.navbar, bg="#333344")
        self.profile_frame.pack(side="right", padx=10)

        self.profile_button = None
        self.update_profile_section()

        tk.Button(
            self.navbar, text="Contact Us", bg="#444455", fg="white", command=self.contact_us
        ).pack(side="left", padx=10, pady=5)

        # Add Help Icon
        help_icon_image = Image.open("imgs/help.png")
        help_icon_photo = ImageTk.PhotoImage(help_icon_image.resize((30, 30)))  # Resize if needed
        self.help_button = tk.Button(
            self.navbar, image=help_icon_photo, bg="#333344", command=self.open_help
        )
        self.help_button.image = help_icon_photo  # Keep a reference to avoid garbage collection
        self.help_button.pack(side="left", padx=10, pady=5)

    def create_workspace(self):
        # Main workspace frame
        self.workspace = ttk.Frame(self.root)
        self.workspace.place(x=0, y=50, width=1200, height=750)

        # Left panel for controls
        left_panel = ttk.Frame(self.workspace)
        left_panel.pack(side="left", fill="y", padx=10, pady=10)

        # Control buttons
        ttk.Button(left_panel, text="Load Data", command=self.load_data).pack(pady=5, fill="x")
        ttk.Button(left_panel, text="Perform Clustering", command=self.perform_clustering).pack(pady=5, fill="x")
        ttk.Button(left_panel, text="Train & Predict", command=self.train_predict).pack(pady=5, fill="x")
        ttk.Button(left_panel, text="Export Results", command=self.export_results).pack(pady=5, fill="x")

        # Right panel for displaying data structure
        right_panel = ttk.Frame(self.workspace)
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        # Text widget for displaying data structure
        self.structure_text = tk.Text(right_panel, wrap=tk.WORD)
        self.structure_text.pack(fill="both", expand=True)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.structure_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.structure_text.configure(yscrollcommand=scrollbar.set)

    def update_profile_section(self):
        for widget in self.profile_frame.winfo_children():
            widget.destroy()

        if self.current_user is not None:
            # Display Profile Dropdown
            self.profile_button = tk.Menubutton(
                self.profile_frame, text=self.current_user, bg="#444455", fg="white", relief="raised"
            )
            menu = tk.Menu(self.profile_button, tearoff=0)
            menu.add_command(label="Settings", command=self.open_settings)
            menu.add_command(label="Logout", command=self.logout)
            self.profile_button.config(menu=menu)
            self.profile_button.pack(side="right", padx=10, pady=5)
        else:
            # Display Login/Signup Button
            self.login_button = tk.Button(
                self.profile_frame, text="Login/Signup", bg="#444455", fg="white", command=self.login_signup
            )
            self.login_button.pack(side="right", padx=10, pady=5)

    def login_signup(self):
        # Create a Login/Signup Dialog
        login_window = tk.Toplevel(self.root)
        login_window.title("Login/Signup")
        login_window.geometry("400x300")

        ttk.Label(login_window, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(login_window)
        username_entry.pack(pady=5)

        ttk.Label(login_window, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(login_window, show="*")
        password_entry.pack(pady=5)

        def login():
            username = username_entry.get()
            password = password_entry.get().encode('utf-8')
            if username in self.users and bcrypt.checkpw(password, self.users[username].encode('utf-8')):
                messagebox.showinfo("Login Successful", f"Welcome, {username}!")
                self.current_user = username
                self.update_profile_section()
                login_window.destroy()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

        def signup():
            username = username_entry.get()
            password = password_entry.get().encode('utf-8')
            if username in self.users:
                messagebox.showerror("Signup Failed", "Username already exists.")
            else:
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
                self.users[username] = hashed_password
                self.save_users()  # Save to JSON
                messagebox.showinfo("Signup Successful", f"Account created for {username}!")
                self.current_user = username
                self.update_profile_section()
                login_window.destroy()

        ttk.Button(login_window, text="Login", command=login).pack(pady=10)
        ttk.Button(login_window, text="Signup", command=signup).pack(pady=10)


    def contact_us(self):
        messagebox.showinfo(
            "Contact Us", "Email: support@redshifttool.com\nPhone: +918660578359"
        )

    def open_help(self):
        documentation = """
        Welcome to the Photometric Redshift Estimation Tool!

        Features:
        - Load your CSV or FITS data files using the 'Load Data' option.
        - Perform clustering to group data based on photometric properties.
        - Train and predict redshifts using advanced machine learning models.
        - Export the results as a CSV file for further analysis.

        Navigation:
        - Use the 'Login/Signup' button to create an account or log in.
        - Click 'Contact Us' for support information.
        - Use the Help (?) button for guidance.

        For assistance, contact support@redshifttool.com.
        """
        messagebox.showinfo("Help", documentation)

    def load_data(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv"), ("FITS files", "*.fits")]
        )
        if file_path:
            try:
                # Load the data
                if file_path.endswith(".csv"):
                    data = pd.read_csv(file_path)
                elif file_path.endswith(".fits"):
                    with fits.open(file_path) as hdul:
                        data = pd.DataFrame(hdul[1].data)  # Use the first table extension
                else:
                    raise ValueError("Unsupported file format.")

                # Display the structure
                self.display_structure(data, file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load data: {e}")

    def display_structure(self, data, file_path):
        # Clear the Text widget
        self.structure_text.delete(1.0, tk.END)

        # Display dataset structure
        self.structure_text.insert(tk.END, f"File: {file_path}\n")
        self.structure_text.insert(tk.END, "=" * 80 + "\n")
        self.structure_text.insert(tk.END, "Dataset Structure:\n")
        self.structure_text.insert(tk.END, f"Number of Rows: {data.shape[0]}\n")
        self.structure_text.insert(tk.END, f"Number of Columns: {data.shape[1]}\n")
        self.structure_text.insert(tk.END, "\nColumn Information:\n")
        self.structure_text.insert(tk.END, data.dtypes.to_string())

    def perform_clustering(self):
        messagebox.showinfo("Perform Clustering", "Clustering functionality is under development.")

    def train_predict(self):
        messagebox.showinfo("Train & Predict", "Training and prediction functionality is under development.")

    def export_results(self):
        messagebox.showinfo("Export Results", "Export functionality is under development.")

    def open_settings(self):
        messagebox.showinfo("Settings", "Settings functionality is under development.")

    def logout(self):
        self.current_user = None
        self.update_profile_section()
        messagebox.showinfo("Logout", "You have been logged out.")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = RedshiftApp(root)
    root.mainloop()

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import pandas as pd
from astropy.io import fits
import json
import bcrypt

class ModernButton(tk.Button):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.default_bg = kwargs.get('bg', '#2D3250')
        self.hover_bg = '#414B77'
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.configure(
            relief='flat',
            borderwidth=0,
            padx=15,
            pady=8,
            font=('Helvetica', 10),
            fg='white',
            bg=self.default_bg,
            activebackground=self.hover_bg,
            activeforeground='white',
            cursor='hand2'
        )

    def on_enter(self, e):
        self.configure(bg=self.hover_bg)

    def on_leave(self, e):
        self.configure(bg=self.default_bg)

class ModernMenuButton(tk.Menubutton):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.default_bg = kwargs.get('bg', '#2D3250')
        self.hover_bg = '#414B77'
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.configure(
            relief='flat',
            borderwidth=0,
            padx=15,
            pady=8,
            font=('Helvetica', 10),
            fg='white',
            bg=self.default_bg,
            activebackground=self.hover_bg,
            cursor='hand2'
        )

    def on_enter(self, e):
        self.configure(bg=self.hover_bg)

    def on_leave(self, e):
        self.configure(bg=self.default_bg)

class RedshiftApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Photometric Redshift Estimation Tool")
        self.root.geometry("1200x800")
        
        # Set color scheme
        self.colors = {
            'bg': '#1B1E2F',
            'nav': '#2D3250',
            'accent': '#7C83FD',
            'text': '#FFFFFF',
            'button': '#2D3250',
            'hover': '#414B77'
        }
        
        # Configure root background
        self.root.configure(bg=self.colors['bg'])
        
        # Configure fonts
        self.fonts = {
            'header': ('Helvetica', 12, 'bold'),
            'body': ('Helvetica', 10),
            'small': ('Helvetica', 9)
        }

        # Initialize user-related attributes
        self.users = self.load_users()
        self.current_user = None

        # Create UI elements
        self.setup_background()
        self.create_navbar()
        self.create_workspace()
        self.configure_styles()

    def configure_styles(self):
        style = ttk.Style()
        style.configure(
            "Vertical.TScrollbar",
            background=self.colors['nav'],
            troughcolor=self.colors['bg'],
            width=10
        )

    def setup_background(self):
        try:
            self.background_image = Image.open("imgs/bg.png")
            gradient = Image.new('RGBA', self.background_image.size, (27, 30, 47, 180))
            self.background_image = Image.alpha_composite(
                self.background_image.convert('RGBA'), gradient
            )
            self.background_photo = ImageTk.PhotoImage(self.background_image)
            
            self.canvas = tk.Canvas(
                self.root,
                width=1200,
                height=800,
                highlightthickness=0
            )
            self.canvas.pack(fill="both", expand=True)
            self.canvas.create_image(0, 0, image=self.background_photo, anchor="nw")
        except FileNotFoundError:
            self.root.configure(bg=self.colors['bg'])

    def load_users(self):
        try:
            with open("users.json", "r") as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    def save_users(self):
        with open("users.json", "w") as file:
            json.dump(self.users, file)

    def open_settings(self):
        messagebox.showinfo("Settings", "Settings panel coming soon")

    def logout(self):
        self.current_user = None
        self.update_profile_section()
        messagebox.showinfo("Logout", "Successfully logged out")

    def contact_us(self):
        messagebox.showinfo("Contact Us", "For support, email: support@redshift.com")

    def open_help(self):
        help_window = tk.Toplevel(self.root)
        help_window.title("Help & Documentation")
        help_window.geometry("600x400")
        help_window.configure(bg=self.colors['bg'])

        # Header
        tk.Label(
            help_window,
            text="Help & Documentation",
            font=('Helvetica', 14, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['accent']
        ).pack(pady=10)

        # Text Box
        help_text = tk.Text(
            help_window,
            wrap=tk.WORD,
            bg=self.colors['nav'],
            fg=self.colors['text'],
            font=self.fonts['body'],
            padx=10,
            pady=10,
            relief='flat',
            insertbackground=self.colors['text']
        )
        help_text.pack(fill="both", expand=True, padx=10, pady=10)

        # Load Help Content
        try:
            with open("docs/help.txt", "r") as file:
                help_text.insert("1.0", file.read())
        except FileNotFoundError:
            help_text.insert("1.0", "Help documentation not found. Please ensure 'docs/help.txt' exists.")

        # Disable Editing
        help_text.config(state=tk.DISABLED)


    def create_navbar(self):
        self.navbar = tk.Frame(self.root, bg=self.colors['nav'], height=60)
        self.navbar.place(x=0, y=0, width=1200)

        # Title
        title_label = tk.Label(
            self.navbar,
            text="Redshift",
            font=('Helvetica', 16, 'bold'),
            bg=self.colors['nav'],
            fg=self.colors['accent']
        )
        title_label.pack(side="left", padx=20)

        # Profile Section
        self.profile_frame = tk.Frame(self.navbar, bg=self.colors['nav'])
        self.profile_frame.pack(side="right", padx=20)

        # Contact Us button
        ModernButton(
            self.navbar,
            text="Contact Us",
            command=self.contact_us,
            bg=self.colors['button']
        ).pack(side="left", padx=10)

        # Help button
        try:
            help_icon_image = Image.open("imgs/help.png")
            help_icon_photo = ImageTk.PhotoImage(help_icon_image.resize((24, 24)))
            self.help_button = ModernButton(
                self.navbar,
                image=help_icon_photo,
                bg=self.colors['nav'],
                command=self.open_help
            )
            self.help_button.image = help_icon_photo
            self.help_button.pack(side="left", padx=10)
        except FileNotFoundError:
            ModernButton(
                self.navbar,
                text="?",
                command=self.open_help,
                bg=self.colors['nav']
            ).pack(side="left", padx=10)

        self.update_profile_section()

    def create_workspace(self):
        self.workspace = tk.Frame(self.root, bg=self.colors['bg'])
        self.workspace.place(x=0, y=60, width=1200, height=740)

        # Left panel
        left_panel = tk.Frame(self.workspace, bg=self.colors['bg'])
        left_panel.pack(side="left", fill="y", padx=20, pady=20)

        # Control buttons
        buttons = [
            ("Load Data", self.load_data),
            ("Perform Clustering", self.perform_clustering),
            ("Train & Predict", self.train_predict),
            ("Export Results", self.export_results)
        ]

        for text, command in buttons:
            btn = ModernButton(
                left_panel,
                text=text,
                command=command,
                width=20
            )
            btn.pack(pady=10)

        # Right panel
        right_panel = tk.Frame(self.workspace, bg=self.colors['bg'])
        right_panel.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        # Text widget
        self.structure_text = tk.Text(
            right_panel,
            wrap=tk.WORD,
            bg=self.colors['nav'],
            fg=self.colors['text'],
            font=self.fonts['body'],
            padx=10,
            pady=10,
            relief='flat',
            insertbackground=self.colors['text']
        )
        self.structure_text.pack(fill="both", expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(right_panel, orient="vertical", command=self.structure_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.structure_text.configure(yscrollcommand=scrollbar.set)

    def update_profile_section(self):
        for widget in self.profile_frame.winfo_children():
            widget.destroy()

        if self.current_user is not None:
            try:
                # Load and display profile icon
                profile_icon = Image.open("imgs/profile.png")
                profile_icon = profile_icon.resize((32, 32))
                profile_photo = ImageTk.PhotoImage(profile_icon)
                
                self.profile_button = ModernMenuButton(
                    self.profile_frame,
                    image=profile_photo,
                    bg=self.colors['nav'],
                )
                self.profile_button.image = profile_photo
                
                # Create custom dropdown menu
                menu = tk.Menu(
                    self.profile_button,
                    tearoff=0,
                    bg=self.colors['nav'],
                    fg=self.colors['text'],
                    activebackground=self.colors['hover'],
                    activeforeground=self.colors['text'],
                    relief='flat',
                    bd=0,
                    font=self.fonts['body']
                )
                
                # Add username as first item (non-clickable)
                menu.add_command(
                    label=f"Signed in as\n{self.current_user}",
                    state='disabled',
                    background=self.colors['nav'],
                    foreground=self.colors['accent']
                )
                menu.add_separator()
                menu.add_command(label="Profile", command=lambda: messagebox.showinfo("Profile", "Profile view coming soon"))
                menu.add_command(label="Settings", command=self.open_settings)
                menu.add_separator()
                menu.add_command(label="Logout", command=self.logout)
                
                self.profile_button.config(menu=menu)
                self.profile_button.pack(side="right")
            except FileNotFoundError:
                # Fallback to text-based button if image not found
                self.create_text_based_profile_button()
        else:
            ModernButton(
                self.profile_frame,
                text="Login/Signup",
                command=self.login_signup,
                bg=self.colors['button']
            ).pack(side="right")

    def create_text_based_profile_button(self):
        self.profile_button = ModernMenuButton(
            self.profile_frame,
            text=self.current_user[:1].upper(),  # First letter of username
            bg=self.colors['button'],
            width=3
        )
        # Add the same menu configuration as above
        menu = tk.Menu(
            self.profile_button,
            tearoff=0,
            bg=self.colors['nav'],
            fg=self.colors['text'],
            activebackground=self.colors['hover'],
            activeforeground=self.colors['text'],
            relief='flat',
            bd=0,
            font=self.fonts['body']
        )
        
        menu.add_command(
            label=f"Signed in as\n{self.current_user}",
            state='disabled',
            background=self.colors['nav'],
            foreground=self.colors['accent']
        )
        menu.add_separator()
        menu.add_command(label="Profile", command=lambda: messagebox.showinfo("Profile", "Profile view coming soon"))
        menu.add_command(label="Settings", command=self.open_settings)
        menu.add_separator()
        menu.add_command(label="Logout", command=self.logout)
        
        self.profile_button.config(menu=menu)
        self.profile_button.pack(side="right")

    def login_signup(self):
        login_window = tk.Toplevel(self.root)
        login_window.title("Login/Signup")
        login_window.geometry("400x300")
        login_window.configure(bg=self.colors['bg'])

        # Username field
        username_frame = tk.Frame(login_window, bg=self.colors['bg'])
        username_frame.pack(pady=10, padx=20, fill="x")
            
        tk.Label(
            username_frame,
            text="Username:",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=self.fonts['body']
        ).pack(anchor="w")
            
        username_entry = tk.Entry(
            username_frame,
            font=self.fonts['body'],
            bg=self.colors['nav'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief='flat'
        )
        username_entry.pack(fill="x", pady=(5, 0))

        # Password field
        password_frame = tk.Frame(login_window, bg=self.colors['bg'])
        password_frame.pack(pady=10, padx=20, fill="x")
            
        tk.Label(
            password_frame,
            text="Password:",
            bg=self.colors['bg'],
            fg=self.colors['text'],
            font=self.fonts['body']
        ).pack(anchor="w")
            
        password_entry = tk.Entry(
            password_frame,
            font=self.fonts['body'],
            bg=self.colors['nav'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief='flat',
            show="●"            )
        password_entry.pack(fill="x", pady=(5, 0))

        # Buttons
        button_frame = tk.Frame(login_window, bg=self.colors['bg'])
        button_frame.pack(pady=20)

        ModernButton(
            button_frame,
            text="Login",
            command=lambda: self.handle_login(
                login_window, username_entry.get(), password_entry.get()                )
            ).pack(side="left", padx=10)

        ModernButton(
            button_frame,
            text="Signup",
            command=lambda: self.handle_signup(
                login_window, username_entry.get(), password_entry.get()
            )
        ).pack(side="left", padx=10)

    def handle_login(self, window, username, password):
        if username in self.users and bcrypt.checkpw(
            password.encode('utf-8'),
            self.users[username].encode('utf-8')
        ):
            messagebox.showinfo("Success", f"Welcome back, {username}!")
            self.current_user = username
            self.update_profile_section()
            window.destroy()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def handle_signup(self, window, username, password):
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
        else:
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            self.users[username] = hashed_password
            self.save_users()
            messagebox.showinfo("Success", f"Welcome, {username}!")
            self.current_user = username
            self.update_profile_section()
            window.destroy()

    def load_data(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv"), ("FITS files", "*.fits")]
        )
        if file_path:
            try:
                if file_path.endswith(".csv"):
                    data = pd.read_csv(file_path)
                elif file_path.endswith(".fits"):
                    with fits.open(file_path) as hdul:
                        data = pd.DataFrame(hdul[1].data)
                else:
                    raise ValueError("Unsupported file format")

                self.display_structure(data, file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load data: {str(e)}")

    def display_structure(self, data, file_path):
        self.structure_text.delete('1.0', tk.END)
        
        self.structure_text.tag_configure('header', font=self.fonts['header'])
        self.structure_text.tag_configure('info', font=self.fonts['body'])
        
        # File info
        self.structure_text.insert('end', "File: ", 'header')
        self.structure_text.insert('end', f"{file_path}\n\n", 'info')
        
        # Dataset structure
        self.structure_text.insert('end', "Dataset Structure:\n", 'header')
        self.structure_text.insert('end', f"Number of Rows: {data.shape[0]}\n", 'info')
        self.structure_text.insert('end', f"Number of Columns: {data.shape[1]}\n\n", 'info')
        
        # Column information
        self.structure_text.insert('end', "Column Information:\n", 'header')
        self.structure_text.insert('end', data.dtypes.to_string(), 'info')

    def perform_clustering(self):
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please log in to use this feature")
            return
        messagebox.showinfo("Info", "Clustering functionality is under development")

    def train_predict(self):
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please log in to use this feature")
            return
        messagebox.showinfo("Info", "Training and prediction functionality is under development")

    def export_results(self):
        if not self.current_user:
            messagebox.showwarning("Login Required", "Please log in to use this feature")
            return
        
        # Prompt user to select save location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Export Results"
        )
        
        if file_path:
            try:
                # Check if results data is available
                if hasattr(self, 'data') and not self.data.empty:
                    self.data.to_csv(file_path, index=False)
                    messagebox.showinfo(
                        "Export Successful",
                        f"Results successfully exported to:\n{file_path}"
                    )
                else:
                    messagebox.showwarning(
                        "No Data to Export",
                        "Please load data or generate results before exporting."
                    )
            except Exception as e:
                messagebox.showerror(
                    "Export Failed",
                    f"An error occurred while exporting the data:\n{str(e)}"
                )
    

if __name__ == "__main__":
    root = tk.Tk()
    app = RedshiftApp(root)
    root.mainloop()

import customtkinter as ctk
import string
import secrets
import re
import random
import hashlib  # Added for API hashing
import requests # Added for API requests

# APPEARANCE CUSTOMIZATION
ctk.set_appearance_mode("Dark") 
ctk.set_default_color_theme("blue") 

class PasswordApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SecurePass Utility")
        self.geometry("500x600")

        # Main background container
        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        self.show_main_menu()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_main_menu(self):
        self.clear_container()
        
        ctk.CTkLabel(self.container, text="Password Centre", font=("Impact", 35), text_color="#3a7ebf").pack(pady=40)
        
        # We can use hex codes for any color!
        ctk.CTkButton(self.container, text="CHECK STRENGTH", command=self.show_strength_page, 
                      fg_color="#3d7cb7", hover_color="#2a5a8a", height=50, width=280).pack(pady=10)
        
        ctk.CTkButton(self.container, text="GENERATE PASSWORD", command=self.show_generator_page, 
                      fg_color="#3a7ebf", hover_color="#2a5a8a", height=50, width=280).pack(pady=10)
        
        ctk.CTkButton(self.container,text="QUIZ",command=self.show_quiz_page,
                      fg_color="#3a7ebf",hover_color="#2a5a8a",height=50,width=280).pack(pady=10)
        
        ctk.CTkButton(self.container,text="FAQ",command=self.show_faq_page,
                      fg_color="#3a7ebf",hover_color="#2a5a8a",height=50,width=280).pack(pady=10)

        
        ctk.CTkButton(self.container, text="EXIT PROGRAM", command=self.quit, 
                      fg_color="#922b21", hover_color="#7b241c", height=50, width=280).pack(pady=10)

    def show_strength_page(self):
        self.clear_container()
        ctk.CTkLabel(self.container, text="STRENGTH CHECKER", font=("Impact", 25)).pack(pady=20)
        
        # 'show' parameter is removed so password is VISIBLE
        pw_entry = ctk.CTkEntry(self.container, placeholder_text="Type password here...", 
                                width=350, height=40, font=("Consolas", 14))
        pw_entry.pack(pady=10)

        result_label = ctk.CTkLabel(self.container, text="Results will appear here", font=("Arial", 13, "italic"))
        result_label.pack(pady=20)

        def check():
            pw = pw_entry.get()
            if not pw: return
            res = self.pass_check_logic(pw)
            # Dynamic coloring based on strength
           
            if res[0] == "Strong Password":
                 color = "#27ae60"
            elif res[0]=="Weak Password" :
                 color="#f76e95"
            else:
                color="#e67e22"
            result_label.configure(text=f"{res[0]}\n{res[1]}", text_color=color, font=("Arial", 14, "bold"))

        ctk.CTkButton(self.container, text="ANALYZE", command=check, fg_color="#3a7ebf").pack(pady=5)
        ctk.CTkButton(self.container, text="BACK", command=self.show_main_menu, fg_color="transparent", border_width=1).pack(pady=20)

    def show_generator_page(self):
        self.clear_container()
        ctk.CTkLabel(self.container, text="GENERATOR SETTINGS", font=("Impact", 25)).pack(pady=20)
        
        # SLIDER SETUP (4 to 32)
        slider_val = ctk.IntVar(value=16)
        
        val_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        val_frame.pack()
        ctk.CTkLabel(val_frame, text="PASSWORD LENGTH: ", font=("Arial", 14, "bold")).pack(side="left")
        ctk.CTkLabel(val_frame, textvariable=slider_val, font=("Arial", 18, "bold"), text_color="#3a7ebf").pack(side="left")

        len_slider = ctk.CTkSlider(self.container, from_=4, to=32, number_of_steps=28, variable=slider_val)
        len_slider.pack(pady=15, fill="x", padx=60)
        
        # Checkboxes for requirements
        up_var, low_var, num_var, sym_var = [ctk.BooleanVar(value=True) for _ in range(4)]

        grid_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        grid_frame.pack(pady=10)
        ctk.CTkCheckBox(grid_frame, text="Uppercase (ABC)", variable=up_var).grid(row=0, column=0, padx=10, pady=5)
        ctk.CTkCheckBox(grid_frame, text="Lowercase (abc)", variable=low_var).grid(row=0, column=1, padx=10, pady=5)
        ctk.CTkCheckBox(grid_frame, text="Numbers (123)", variable=num_var).grid(row=1, column=0, padx=10, pady=5)
        ctk.CTkCheckBox(grid_frame, text="Symbols (!@#)", variable=sym_var).grid(row=1, column=1, padx=10, pady=5)

        result_entry = ctk.CTkEntry(self.container, width=380, height=50, font=("Courier New", 18, "bold"), justify="center")
        result_entry.pack(pady=20)

        def generate():
            pw = self.pass_gen_logic(slider_val.get(), low_var.get(), up_var.get(), num_var.get(), sym_var.get())
            result_entry.delete(0, 'end')
            result_entry.insert(0, pw)

        ctk.CTkButton(self.container, text="GENERATE", command=generate, height=45, fg_color="#3a7ebf").pack(pady=5)
        ctk.CTkButton(self.container, text="BACK", command=self.show_main_menu, fg_color="transparent", border_width=1).pack(pady=10)
        
    def show_quiz_page(self):
            
         self.clear_container()

         self.score = 0
         self.q_no = 0

         self.questions = [
        ("What is a brute-force attack?",
         ["Trying all combinations",
          "Encrypting data",
          "Firewall setup",
          "Phishing email"], 0),

        ("What makes a password strong?",
         ["Short and simple",
          "Long with mixed characters",
          "Personal info",
          "Same everywhere"], 1),
        
        ("What is credential stuffing?",
              ["Random password creation",
               "Using stolen credentials on multiple sites",
               "Encrypting passwords",
               "Blocking users"], 1),

        ("What is phishing?",
              ["Fake emails to steal data",
               "Antivirus",
               "Encryption",
               "Firewall"], 0)]
         random.shuffle(self.questions)

         self.question_label = ctk.CTkLabel(self.container,text="",font=("Arial", 14),wraplength=500)
         self.question_label.pack(pady=20)

         self.var = ctk.IntVar(value=-1)

         self.options = []
         for i in range(4):
          btn = ctk.CTkRadioButton(self.container,text="", variable=self.var,value=i)
          btn.pack(anchor="w", padx=80)
          self.options.append(btn)

         self.feedback_label = ctk.CTkLabel(self.container, text="")
         self.feedback_label.pack(pady=10)

         self.next_button = ctk.CTkButton(
         self.container,
         text="Submit",
         command=self.next_question)
         self.next_button.pack(pady=10)

         ctk.CTkButton(self.container,text="BACK",command=self.show_main_menu).pack(pady=10)
         self.show_question()

    def show_question(self):
        for option in self.options:
            option.configure(state="normal")
        question, options, _ = self.questions[self.q_no]
        self.question_label.configure(text=question)
        self.var.set(-1)
        self.feedback_label.configure(text="")

        for i in range(4):
            self.options[i].configure(text=options[i])

    
    def next_question(self):
      selected = self.var.get()
      question, options, correct = self.questions[self.q_no]

      if selected == -1:
            self.feedback_label.configure(text="Please select an option!",
                                       text_color="yellow")
            return

      if selected == correct:
            self.score += 1
            self.feedback_label.configure(text="Correct ✅",
                                       text_color="lightgreen")
      else:
            correct_answer = options[correct]
            self.feedback_label.configure(
                text=f"Wrong ❌\nCorrect Answer: {correct_answer}",
                text_color="red"
            )

      # Disable options after answering
      for option in self.options:
            option.configure(state="disabled")

      # Move to next question after 1.5 seconds
      self.after(1500, self.go_next)


    def go_next(self):
     self.q_no += 1

     if self.q_no < len(self.questions):
        self.show_question()
     else:
        self.show_result()
      
    def show_result(self):
       self.clear_container()

       percentage = int((self.score / len(self.questions)) * 100)

       ctk.CTkLabel(self.container,text=f"Quiz Completed!\nScore: {self.score}/{len(self.questions)}\nPercentage: {percentage}%",
                    font=("Arial", 16)).pack(pady=50)

       ctk.CTkButton(self.container,text="BACK TO MENU",command=self.show_main_menu).pack(pady=20)
  
    #faq
    def show_faq_page(self):
        self.clear_container()

        faqs = [
        ("How does the password analyzer work?",
         "It checks password length, character variety and estimates brute-force resistance."),

        ("Is this password tool safe?",
         "Yes. Passwords are not stored or sent anywhere. Everything runs locally."),

        ("What makes a strong password?",
         "Use 12+ characters with uppercase, lowercase, numbers and symbols."),

        ("How long should my password be?",
         "Minimum 8 characters, recommended 12–16 characters."),

        ("What is brute force attack?",
         "Attackers try every possible password combination until they guess correctly.")
        ]
        ctk.CTkLabel(self.container,text="Frequently Asked Questions",font=("Impact", 28)).pack(pady=20)

        for question, answer in faqs:
         frame = ctk.CTkFrame(self.container)
         frame.pack( fill="x",padx=20, pady=5)
         answer_label = ctk.CTkLabel(frame,text=answer,wraplength=400,text_color="white" )

         def toggle(lbl=answer_label):
            if lbl.winfo_viewable():
                lbl.pack_forget()
            else:
                lbl.pack( padx=10, pady=4)
         ctk.CTkButton(frame,text=question,command=toggle).pack(fill="x",padx=5, pady=5)

        answer_label.pack(padx=10)
        answer_label.pack_forget()

        ctk.CTkButton(self.container,text="BACK",command=self.show_main_menu).pack(pady=20)

    # --- Logic Methods ---
    def check_pwned_api(self, password):
        """Checks if password has been leaked using HIBP API (SHA-1 k-Anonymity)"""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            if response.status_code != 200: return 0
            
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix: return int(count)
            return 0
        except:
            return -1 # Connection error

    def pass_check_logic(self, password):
        strength = 0
        feedback = []
        if len(password) >= 8: strength += 1
        else: feedback.append("- Needs 8+ characters")
        if re.search(r'[A-Z]', password): strength += 1
        else: feedback.append("- Needs an uppercase")
        if re.search(r'[a-z]', password): strength += 1
        else: feedback.append("- Needs a lowercase")
        if re.search(r'[!@#$%^&*()_\-+=;:<>?/]', password): strength += 1
        else: feedback.append("- Needs a special symbol")
        if re.search(r'[0-9]', password): strength += 1
        else: feedback.append("- Needs a number")
        
        # --- Breach Check Integration ---
        pwned_count = self.check_pwned_api(password)
        breach_info = ""
        if pwned_count > 0:
            breach_info = f"\n\n🚨 WARNING: This password was found in {pwned_count:,} data breaches! DO NOT USE IT."
        elif pwned_count == 0:
            breach_info = "\n\n✅ This password was not found in any known public data breaches."
        # -------------------------------

        crack_time = self.crack_time(password)
        if strength == 5: 
            education=("\n\nWhy this is strong:\n"
        "• Good length increases brute-force resistance.\n"
        "• Mixed character types prevent pattern attacks.\n"
        "• Harder to guess in real-world data breaches.\n\n"
        "Keep using unique passwords for every account!")

            return "Strong Password", f"Security Verified ✓\n{crack_time}{breach_info}{education}"
        
        elif strength >= 3:
            education=(  "\n\nSecurity Advice:\n"
        "Weak patterns are commonly exploited in data breaches.\n"
        "Attackers use automated tools to guess missing character types.\n"
        "Improving the missing elements increases resistance.")
            return "Medium Password", "Missing:\n" + "\n".join(feedback)+f"\n{crack_time}{breach_info}{education}"
        
        else:
            education=(  "\n\n⚠ Security Risk:\n"
        "Short or predictable passwords are cracked within seconds.\n"
        "Data breaches expose weak passwords quickly.\n"
        "Add length, symbols, uppercase letters, and numbers.")
            return"Weak Password", "Missing:\n" + "\n".join(feedback)+f"\n{crack_time}{breach_info}{education}"


    def crack_time(self, password):
        length = len(password)
        char_set=0
        if any(c.islower() for c in password):
            char_set+= 26
        if any(c.isupper()for c in password):
            char_set += 26
        if any(c.isdigit() for c  in password):
            char_set+= 10
        if any(c in string.punctuation for c in password):
            char_set+= 32
        comb=(char_set)**length
        guess_per_sec=1000000000
        time_sec=comb/guess_per_sec
        years=time_sec/(365*24*60*60)
    
        if time_sec<60:
            return f"crack time:{time_sec:.2f} seconds"
        elif time_sec<3600:
            mintues=time_sec/60
            return f"crack time{mintues:.2f} minutes"
        elif time_sec<86400:
            hours=time_sec/3600
            return f"crack time:{hours:.2f} hours"        
        elif years<1:
            return f"Crack Time: {time_sec:.2f} seconds"
        else:
            return f"crack time:{years:.2f} years"
        

    def pass_gen_logic(self, length, include_lowercase, include_uppercase, include_numbers, include_symbols):
        chars = ''
        if include_lowercase: chars += string.ascii_lowercase
        if include_uppercase: chars += string.ascii_uppercase
        if include_numbers: chars += string.digits
        if include_symbols: chars += string.punctuation
        if not chars: return "Error: Select Options"

        while True:
            password = "".join(secrets.choice(chars) for _ in range(length))
            cond = []
            if include_lowercase: cond.append(any(c.islower() for c in password))
            if include_uppercase: cond.append(any(c.isupper() for c in password))
            if include_numbers: cond.append(any(c.isdigit() for c in password))
            if include_symbols: cond.append(any(c in string.punctuation for c in password))
            if all(cond): return password

if __name__ == "__main__":
    app = PasswordApp()
    app.mainloop()
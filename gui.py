import tkinter as tk
from tkinter import messagebox
from node import Node

class GUI:
    def __init__(self, node: Node):
        self.node = node

        self.root = tk.Tk()
        self.root.title('Python Blockchain')
        self.root.geometry('800x600')

        self.text_log = tk.Text(self.root, height=10, width=200)
        self.text_log.pack(side='bottom')

        self.wallet_frame = tk.LabelFrame(self.root, text='Wallet', height=100, width=100)
        self.wallet_frame.pack(side='left', fill='both', expand=True)

        self.balance_text = tk.Label(self.wallet_frame, text='Balance: ')
        self.balance_text.pack()

        self.wallet_balance = tk.Label(self.wallet_frame, text='0')
        self.wallet_balance.pack()

        self.w_refresh_button = tk.Button(self.wallet_frame, text='Refresh', command=self.refresh_button_clicked)
        self.w_refresh_button.pack()

        self.my_address = tk.Label(self.wallet_frame, text='My Address')
        self.my_address.pack()

        self.address_text = tk.Label(self.wallet_frame, text='...')
        self.address_text.pack()

        self.show_address_button = tk.Button(self.wallet_frame, text='Show Address', command=self.show_address_clicked)
        self.show_address_button.pack()


        self.transaction_frame = tk.LabelFrame(self.root, text='Send Money', height=100, width=100)
        self.transaction_frame.pack(side='right', fill='both', expand=True)

        self.label_address = tk.Label(self.transaction_frame, text='Recipient Address')
        self.label_address.pack()

        self.entry_address = tk.Entry(self.transaction_frame, width=50)
        self.entry_address.pack()
        
        self.label_amount = tk.Label(self.transaction_frame, text='Amount:')
        self.label_amount.pack()

        self.entry_amount = tk.Entry(self.transaction_frame, width=5)
        self.entry_amount.pack()

        self.send_button = tk.Button(self.transaction_frame, text='Send Money', command=self.send_button_clicked)
        self.send_button.pack()


    def refresh_button_clicked(self):
        self.wallet_balance['text'] = self.node.get_balance()

    def show_address_clicked(self):
        self.address_text['text'] = self.node.get_address()

    def send_button_clicked(self):
        address = self.entry_address.get()
        amount = self.entry_amount.get()

        if not address or not amount:
            messagebox.showerror('Error', 'Please enter all fields.')
            return

        self.node.send_money(address, int(amount))

    def run(self):
        self.root.mainloop()
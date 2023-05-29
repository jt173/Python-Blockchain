import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from node import Node

# TODO:
# Remove Recent Transactions

# Add the ability to look at blocks
# Add the ability to look at transactions




class GUI:
    def __init__(self, node: Node):
        self.node = node

        self.root = tk.Tk()
        self.root.title('Python Blockchain')
        self.root.geometry('1200x600')

        self.text_log = tk.Text(self.root, height=10, width=200)
        self.text_log.pack(side='bottom')

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)


        # --- Overview Frame ---         

        # My Wallet
        self.overview_frame = tk.Frame(self.notebook, height=400, width=400)
        self.overview_frame.pack(fill='both', expand=True)

        self.wallet_frame = tk.LabelFrame(self.overview_frame, text='My Wallet')
        self.wallet_frame.pack(side='left', fill='both', expand=True)

        self.balance_text = tk.Label(self.wallet_frame, text='Balance: ')
        self.balance_text.pack()

        self.wallet_balance = tk.Label(self.wallet_frame, text=str(node.get_balance()) + ' Coins')
        self.wallet_balance.pack()

        self.w_refresh_button = tk.Button(self.wallet_frame, text='Refresh', command=self.refresh_button_clicked)
        self.w_refresh_button.pack()

        self.my_address = tk.Label(self.wallet_frame, text='My Address')
        self.my_address.pack()

        self.address_text = tk.Label(self.wallet_frame, text='')
        self.address_text['text'] = self.node.get_address()
        self.address_text.pack()

        # Recent Transactions
        self.recent_tx_frame = tk.LabelFrame(self.overview_frame, text='Recent Transactions')
        self.recent_tx_frame.pack(side='right', fill='both', expand=True)

        self.recent_tx_cols = ('sent_or_recv', 'txid', 'amount')

        self.recent_tx_tree = ttk.Treeview(self.recent_tx_frame, columns=self.recent_tx_cols, show='headings')
        self.recent_tx_tree.column('sent_or_recv', width=60)
        self.recent_tx_tree.column('txid', width=500)
        self.recent_tx_tree.column('amount', width=50)

        # Define headings
        self.recent_tx_tree.heading('sent_or_recv', text='Sent or Received')
        self.recent_tx_tree.heading('txid', text='Transaction ID')
        self.recent_tx_tree.heading('amount', text='Amount')

        self.recent_tx_scrollbar = ttk.Scrollbar(self.recent_tx_frame, orient=tk.VERTICAL, 
                                                 command=self.recent_tx_tree.yview)
        self.recent_tx_tree.configure(yscroll=self.recent_tx_scrollbar.set)
        self.recent_tx_scrollbar.pack(side='right', fill='y')
        self.recent_tx_tree.pack(expand=True, fill='both')

        self.notebook.add(self.overview_frame, text='Overview')


        # --- Send Money Frame ---

        self.send_frame = tk.Frame(self.notebook, height=400, width=400)
        self.send_frame.pack(fill='both', expand=True)

        self.label_address = tk.Label(self.send_frame, text='Recipient Address')
        self.label_address.pack()

        self.entry_address = tk.Entry(self.send_frame, width=50)
        self.entry_address.pack()
        
        self.label_amount = tk.Label(self.send_frame, text='Amount:')
        self.label_amount.pack()

        self.entry_amount = tk.Entry(self.send_frame, width=5)
        self.entry_amount.pack()

        self.send_button = tk.Button(self.send_frame, text='Send Money', command=self.send_button_clicked)
        self.send_button.pack()

        self.notebook.add(self.send_frame, text='Send Money')


        # --- Miner Frame ---

        self.miner_frame = tk.Frame(self.notebook, height=400, width=400)
        self.miner_frame.pack(fill='both', expand=True)

        self.miner_button = tk.Button(self.miner_frame, text='Start Mining', command=self.miner_button_clicked)
        self.miner_button.pack()

        self.notebook.add(self.miner_frame, text='Mine Coins')

        
        # --- Transaction Explorer ---

        self.tx_frame = tk.Frame(self.notebook, height=400, width=400)
        self.tx_frame.pack(fill='both', expand=True)

        self.notebook.add(self.tx_frame, text='Transactions')


        # --- Block Explorer ---

        self.block_frame = tk.Frame(self.notebook, height=400, width=400)
        self.block_frame.pack(fill='both', expand=True)

        self.notebook.add(self.block_frame, text='Blocks')




    def refresh_button_clicked(self):
        self.wallet_balance['text'] = str(self.node.get_balance()) + ' Coins'

    def send_button_clicked(self):
        address = self.entry_address.get()
        amount = self.entry_amount.get()

        if not address or not amount:
            messagebox.showerror('Error', 'Please enter all fields.')
            return
        
        self.node.log_message(f'Attempting to send {amount} coins to {address}')
        self.node.send_money(address, int(amount))

    def miner_button_clicked(self):
        self.node.miner()

    def run(self):
        self.root.mainloop()
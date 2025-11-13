from visualizer import NetworkGUI
import tkinter as tk

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = NetworkGUI(root)
        root.mainloop()
    except ImportError as e:
        print(f"ImportError: {e}. Please ensure all required libraries (scapy, matplotlib, tkinter) are installed.")
        print("You might need to run: pip install scapy matplotlib")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
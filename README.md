🚀 4n0n-BOTNETV1.1 DDoS with C2 Server 🚀
    
    This project is a simple implementation of a Botnet DDoS with a Command and Control (C2) Server. The bot connects to the C2 server and receives commands to launch DDoS attacks on specified targets.

📋 Features

    C2 Server: Controls the bot and sends attack commands.

    Bot: Receives commands from the C2 server and performs DDoS attacks.

    Encryption: Communication between the C2 server and bot is encrypted using AES.

    Multi-Platform: Works on Linux, Windows, macOS, and Termux.

    Stylish Interface: Uses the rich library for an attractive terminal display.

🛠️ Installation

Linux 🐧

      sudo apt update
      sudo apt install python3 python3-pip
      git clone https://github.com/EastTimorGhostSecurity/4n0n-BOTNETV1.1.git
      cd 4n0n-BOTNETV1.1
      pip install pycryptodome scapy rich
      sudo python3 4n0n-BOTNETV1.1.py
      sudo python3 bot.py

Windows 🪟

      git clone https://github.com/EastTimorGhostSecurity/4n0n-BOTNETV1.1.git
      cd 4n0n-BOTNETV1.1
      pip install pycryptodome scapy rich
      python3 4n0n-BOTNETV1.1.py
      python3 bot.py

macOS 🍏

      brew install python
      git clone https://github.com/EastTimorGhostSecurity/4n0n-BOTNETV1.1.git
      cd 4n0n-BOTNETV1.1
      pip install pycryptodome scapy rich
      sudo python3 4n0n-BOTNETV1.1.py
      sudo python3 bot.py

Termux 📱

      pkg update
      pkg install python
      git clone https://github.com/EastTimorGhostSecurity/4n0n-BOTNETV1.1.git
      cd 4n0n-BOTNETV1.1
      pip install pycryptodome scapy rich
      python3 4n0n-BOTNETV1.1.py
      python3 bot.py

🖥️ Usage

   Run the C2 Server:

    The server will run on the IP and port specified in config.py.

    Once the bot connects, the server will prompt for the target IP and target port.

   Run the Bot:

    The bot will attempt to connect to the C2 server.

    Once connected, the bot will receive commands from the C2 server.

   Start the Attack:

    The C2 server will send a command to the bot to start the DDoS attack.

   Stop the Attack:

    Use Ctrl+C to stop the C2 

📝 Notes

    For Educational Purposes Only: This project is created solely for educational purposes. Do not use it for illegal activities.

    Use Responsibly: Ensure you have permission before launching any DDoS attacks.

🙏 Acknowledgments

    Thank you for using this project! If you like it, don't forget to give it a ⭐ on the repository.

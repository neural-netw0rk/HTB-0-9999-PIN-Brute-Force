<img width="1701" height="992" alt="image" src="https://github.com/user-attachments/assets/73c54d97-9389-49c6-afc1-6230c29e6687" />

  
features:

                                         
  - Port scanner: common/range/full 65k, banners, CVE hints                                                                                              
  - HTTP probe: path fuzzing, headers, title, interesting endpoints                                                                                      
  - Brute forcer: numeric PIN and wordlist mode, GET/POST, hit detection                                                                                 
  - Reverse shell generator: 12 payload types, auto IP detection
  - Netcat listener: in-browser with live output stream
  - HTTP repeater: custom requests, response viewer, request history
  - Payload arsenal: SQLi, XSS, SSTI, LFI, CMDi, XXE, SSRF, NoSQL
  - Credential vault: localStorage, Hydra command generator, JSON export
  - Encoder/decoder: Base64, Hex, URL, ROT13, HTML entities, JWT
  - Hash identifier: 16 patterns with hashcat and john modes
  - Notes: persistent localStorage scratchpad
  - 3D globe: geolocation, ambient threat map, real-time scan effects


  
  Start it                                                                                                                                               
                                                                                                                                                         
  cd ~/pin-dashboard                                                                                                                                     
  python3 app.py

  Open http://localhost:5001 in your browser.

  ---
  Connect to HTB

  1. Go to https://hackthebox.com → log in
  2. Starting Point or Machines → pick a box → Spawn Machine
  3. Download the VPN pack → Connect to HTB:
  sudo openvpn ~/Downloads/your-username.ovpn
  4. HTB gives you a target IP like 10.10.11.42

  ---
  Use the dashboard

  Recon tab:
  - Paste 10.10.11.42 into the IP field
  - Hit ▶ Scan Target
  - Watch ports appear in the Findings panel
  - HTTP services get auto-probed for common paths

  Attack tab (after recon):
  - Click → Atk next to any open port in Findings — it pre-fills everything
  - Or manually paste:
    - PIN challenge → http://10.10.11.42:PORT/pin?pin={word}, Numeric mode
    - Login form → POST, body username=admin&password={word}, load Passwords preset
    - Dir fuzz → http://10.10.11.42:PORT/{word}, Wordlist → Dirs preset, Status 200

  To make it accessible from anywhere (e.g. watch from your phone):
  ssh -o StrictHostKeyChecking=no -R 80:localhost:5001 nokey@localhost.run

  ---

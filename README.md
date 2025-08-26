<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation]

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file with the string "tor" and discovered that user **labuser** on the **alex-threat-hun** device downloaded a TOR installer. This action resulted in many TOR-related files being created on the desktop, including a file named `tor-shopping.txt.txt` in the Downloads folder. The events occurred around `Aug 25, 2025 3:52:28 PM`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "alex-threat-hun"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-08-25T15:00:00Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64". Based on the logs, at `Aug 25, 2025 3:29:31 PM`, user **labuser** on the **alex-threat-hun** device ran the file `tor-browser-windows-x86_64-portable-14.5.6.exe` from their Downloads folder. This confirmed the execution of the installer.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "alex-threat-hun"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user **labuser** actually opened the TOR browser. Evidence shows they did, with the spawning of `tor.exe` and several instances of `firefox.exe` on `Aug 25, 2025`, starting at approximately `3:34:47 PM`.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "alex-threat-hun"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On `Aug 25, 2025`, user **labuser** on the **alex-threat-hun** device successfully established connections from the `tor.exe` process to the Tor network. Key connections were observed on ports `9001` and `9030`, which are used for Tor relays, and on port `443` for encrypted traffic.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "alex-threat-hun"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `Aug 25, 2025 3:29:12 PM`
- **Event:** The user "labuser" downloaded and renamed the file `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download and rename detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `Aug 25, 2025 3:29:31 PM`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.5.6.exe`, initiating the installation or extraction of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.6.exe`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `Aug 25, 2025 3:34:47 PM`
- **Event:** User "labuser" launched the TOR browser. This was confirmed by the creation of multiple associated processes, including `tor.exe` and several `firefox.exe` child processes, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `Aug 25, 2025 3:35:09 PM`
- **Event:** A network connection to IP `51.89.242.31` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `Aug 25, 2025 3:35:13 PM` - Connected to `80.79.117.42` on port `443`.
  - `Aug 25, 2025 3:35:27 PM` - Local connection to `127.0.0.1` on port `9150`.
  - `Aug 25, 2025 3:35:38 PM` - Connected to `95.216.19.41` on port `9030`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "labuser" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `Aug 25, 2025 3:52:28 PM`
- **Event:** The user "labuser" created and modified a file named `tor-shopping.txt.txt` in their Downloads folder, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-shopping.txt.txt`

---

## Summary

The user "labuser" on the "alex-threat-hun" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their system, including a file named `tor-shopping.txt.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `alex-threat-hun` by the user `labuser`. The device should be isolated immediately, and the user's direct manager should be notified.

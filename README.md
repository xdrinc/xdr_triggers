# **Cisco XDR Trigger Script - Automated Alert Generation**

## **Overview**
This script is designed to simulate **various security threats and attack techniques** to help customers validate their **Cisco (XDR) PoV**. It runs controlled, benign-but-scary-looking security tests that generate alerts, allowing security teams to **evaluate detection capabilities, fine-tune policies, and enhance threat response workflows**.

## **Tests Included**
The script executes simulations based on **MITRE ATT&CK Tactics & Techniques**. Each test triggers specific behaviors that should be detected by an XDR platform.

### **1️⃣ Endpoint Detection and Response (EDR) Tests**
✅ **T1003.001 - LSASS Memory Dump** (Simulates credential dumping via `rundll32.exe`)  
✅ **T1059.001 - PowerShell Download of Mimikatz** (Simulates execution of an in-memory attack tool)

### **2️⃣ Network Visibility Module (NVM) Tests**
✅ **T1027.010 - Base64 Encoding Obfuscation** (Tests command obfuscation detection)  
✅ **T1059.001 - Connection to Raw Public IP** (Simulates accessing a suspicious IP)  
✅ **T1090.003 - Multi-hop Proxy via TOR Exit Node** (Tests proxy-based evasion techniques)  
✅ **T1105 - Abuse of DNSAPI.DLL for network request** (Simulates DNS-based C2 traffic)

### **3️⃣ Network Detection and Response (NDR) Tests**
✅ **T1041 - Exfiltration Over C2 Channel** (Simulates large data exfiltration over UDP)  
✅ **T1105 - Ingress Tool Transfer** (Simulates malware download attempt)  
✅ **T1046 - Network Service Scanning** (Conducts a local subnet port scan)

### **4️⃣ Firewall Tests**
✅ **T1090 - Connection Proxy** (Tests firewall detection of external proxying)

## **How It Works**
1. **User selects a test or runs all tests** via an interactive menu.  
2. The script **executes security behaviors** corresponding to real-world attack techniques.  
3. Each test **logs results to an HTML report**, recording:
   - **TTP Name**
   - **TTP Number**
   - **Test Result (Success/Failure)**
   - **Timestamp**
   - **MITRE ATT&CK Link** for further reference.  
4. The final report is saved as `XDR_Test_Report.html` for **analysis and sharing**.

## **Benefits for Customers**
✅ **Validates XDR effectiveness** by generating real-world attack behaviors.  
✅ **Helps fine-tune security policies** to improve detection accuracy.  
✅ **Reduces false negatives** by ensuring all expected alerts trigger correctly.  
✅ **Provides documented test results** for compliance and security audits.  
✅ **Enhances incident response workflows** by ensuring security teams can detect and respond efficiently.  

## **Next Steps**
- **Run the script** and analyze how your XDR solution reacts to each test.  
- **Use the report** to identify gaps in detection and improve configurations.  
- **Share results** with security engineers to refine your security posture.  

🚀 **This script enables security teams to continuously validate and improve their XDR defenses.**

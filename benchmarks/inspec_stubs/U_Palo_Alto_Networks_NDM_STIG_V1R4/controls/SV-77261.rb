control 'SV-77261' do
  title 'The Palo Alto Networks security platform must use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW CJCSM 6510.01B.'
  desc 'CJCSM 6510.01B, "Cyber Incident Handling Program", in subsection e.(6)(c) sets forth three requirements for Cyber events detected by an automated system;
If the cyber event is detected by an automated system, an alert will be sent to the POC designated for receiving such automated alerts.
CC/S/A/FAs that maintain automated detection systems and sensors must ensure that a POC for receiving the alerts has been defined and that the IS configured to send alerts to that POC.
The POC must then ensure that the cyber event is reviewed as part of the preliminary analysis phase and reported to the appropriate individuals if it meets the criteria for a reportable cyber event or incident.

By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged on to the network device. An example of a mechanism to facilitate this would be through the utilization of SNMP traps.

The Palo Alto Networks security platform can be configured to send messages to an SNMP server and to an e-mail server as well as a Syslog server.  SNMP traps can be generated for each of the five logging event types on the firewall: traffic, threat, system, hip, config.  For this requirement, only the threat logs must be sent.  Note that only traffic that matches an action in a rule will be logged and forwarded. In the case of traps, the messages are initiated by the firewall and sent unsolicited to the management stations. 

The use of e-mail as a notification method may result in a very larger number of messages being sent and possibly overwhelming the e-mail server as well as the POC.  The use of SNMP is preferred over e-mail in general, but organizations may want to use e-mail in addition to SNMP for high-priority messages.'
  desc 'check', 'Note: The actual method is determined by the organization.
Review the system/network documentation to determine who the Points of Contact are and which methods are being used. 
If the selected method is SNMP, verify that the device is configured.
Go to Device >> Server Profiles
If no SNMP servers are configured, this is a finding.
 
Go to Objects >> Log Forwarding
If no Log Forwarding Profile is listed, this is a finding.

If the "Log Type" column does not include "Threat", this is a finding.

If any Severity is not listed, this is a finding.'
  desc 'fix', 'For SNMP traps, follow the following steps:
Configure the SNMP Trap Destinations; go to 
Device >> Server Profiles >> SNMP Trap
Select "Add".

In the "SNMP Trap Server Profile" window, enter the required information.
For SNMP Version, select "V3". 
Enter the name of the SNMP Server Profile.
Select "Add". 
Server—Specify the SNMP trap destination name (up to 31 characters).
Manager—Specify the IP address of the trap destination.
User—Specify the SNMP user.
EngineID—Specify the engine ID of the firewall. The input is a string in hexadecimal representation. The engine ID is any number between 5 to 64 bytes. When represented as a hexadecimal string, this is between 10 and 128 characters (2 characters for each byte) with two additional characters for 0x that must be used as a prefix in the input string.
Auth Password—Specify the user’s authentication password (minimum 8 characters, maximum of 256 characters, and no character restrictions). Only Secure Hash Algorithm (SHA) is supported.
Priv Password—Specify the user’s encryption password (minimum 8 characters, maximum of 256 characters, and no character restrictions). Only Advanced Encryption Standard (AES) is supported.
Select "OK".

Configure generating "Traps for Threat" events:
Objects >> Log Forwarding
Select "Add".
In the "Log Forwarding Profile" window, enter the required information.
Enter the name of the Log Forwarding Profile.
In the "Threat Settings" section, in the "SNMP Trap" field for each Severity, select the SNMP Trap Server Profile.
Select "OK".

Add the Log Forwarding Profile to the security policies to trigger log forwarding to the SNMP server.
Go to Policies >> Security
Select the rule for which the log forwarding needs to be applied. Apply the security profiles to the rule.
Go to "Actions" (tab); in the "Log forwarding" field, select the "log forwarding" profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62771'
  tag rid: 'SV-77261r1_rule'
  tag stig_id: 'PANW-NM-000131'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-68691r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end

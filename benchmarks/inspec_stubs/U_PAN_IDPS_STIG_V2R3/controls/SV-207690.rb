control 'SV-207690' do
  title 'The Palo Alto Networks security platform must capture traffic of detected/dropped malicious code.'
  desc 'Associating event outcome with detected events in the log provides a means of investigating an attack or suspected attack.

The logs should identify what servers, destination addresses, applications, or databases were potentially attacked by logging communications traffic between the target and the attacker. All commands that were entered by the attacker (such as account creations, changes in permissions, files accessed, etc.) during the session should also be logged when capturing for forensic analysis.

Packet captures of attack traffic can be used by forensic tools for analysis for example, to determine if an alert is real or a false alarm or for forensics for threat intelligence. Configure the packet capture filters so that the CPU is not overloaded.  There are many reasons for a packet capture. This requirement addresses the case where the capture is based on forensics for a detected malicious attack and the traffic is being captured in association with that traffic. Filtering should be engaged to facilitate forensics.'
  desc 'check', 'Go to Objects >> Security Profiles >> Antivirus
View the configured Antivirus Profiles. If the Packet Capture check box is not checked, this is a finding.

Go to Objects >> Security Profiles >> Anti-Spyware
View the configured Anti-Spyware Profiles. If the "Packet Capture" field does not show extended-capture, this is a finding.

Go to Objects >> Security Profiles >> Vulnerability Protection
View the configured Vulnerability Protection Profiles. If the "Packet Capture" field does not show extended-capture, this is a finding.

Go to Policies >> Security
Review each of the configured security policies in turn.  For any Security Policy that affects traffic between Zones (interzone), view the "Profile" column.  If the "Profile" column does not display the Antivirus Profile, Anti-Spyware, and Vulnerability Protection symbols, this is a finding.'
  desc 'fix', 'This procedure will only capture the first packet. See the vendor documentation for further information.

Go to Objects >> Security Profiles >> Antivirus
Select the name of a configured Antivirus Profile or select "Add" to create a new one.
In the "Antivirus Profile" window,  complete the required fields.
In the "Antivirus" tab, select the "Packet Capture" check box.
Select "OK".

Configure an Anti-Spyware Profile to capture detected malicious traffic.
Go to Objects >> Security Profiles >> Anti-Spyware
Select the name of a configured Anti-Spyware Profile or select "Add" to create a new one.
In the "Anti-Spyware Profile" window, complete the required fields in all tabs.
In the "Rules" tab, select the name of a configured Anti-Spyware Rule or select "Add" to create a new one.
In the "Anti-Spyware Rule" window, in the "Packet Capture" field, select "extended-capture".
Select "OK". 
Select "OK" again.

Configure a Vulnerability Protection Profile to capture detected malicious traffic.
Go to Objects >> Security Profiles >> Vulnerability Protection
Select the name of a configured Vulnerability Protection Profile or select "Add" to create a new one.
In the "Vulnerability Protection Profile" window, complete the required fields.
In the "Rules" tab, select the name of a configured Vulnerability Protection Rule or select "Add" to create a new one.
In the "Vulnerability Protection Rule" window, in the "Packet Capture" field, select "extended-capture".
Select "OK".
Select "OK" again.

Use the Antivirus Profile, Anti-Spyware Profile, and Vulnerability Protection Profile in a Security Policy.
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions tab in the Profile Setting section:
In the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Antivirus" field, select the configured Antivirus Profile.
In the "Anti-Spyware" field, select the configured Anti-Spyware Profile.
In the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Select "OK". 
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7944r358403_chk'
  tag severity: 'medium'
  tag gid: 'V-207690'
  tag rid: 'SV-207690r559743_rule'
  tag stig_id: 'PANW-IP-000008'
  tag gtitle: 'SRG-NET-000078-IDPS-00063'
  tag fix_id: 'F-7944r573750_fix'
  tag 'documentable'
  tag legacy: ['SV-77141', 'V-62651']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

control 'SV-207695' do
  title 'The Palo Alto Networks security platform must detect and drop any prohibited mobile or otherwise malicious code at internal boundaries.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code.

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

The Palo Alto Networks security platform allows customized profiles to be used to perform antivirus inspection for traffic between zones. Antivirus, anti-spyware, and vulnerability protection features require a specific license. There is a default Antivirus Profile; the profile inspects all of the listed protocol decoders for viruses, and generates alerts for SMTP, IMAP, and POP3 protocols while dropping for FTP, HTTP, and SMB protocols. However, these default actions cannot be edited and the values for the FTP, HTTP, and SMB protocols do not meet the requirement, so customized profiles must be used."
  desc 'check', 'Go to Objects >> Security Profiles >> Antivirus.

If there are no Antivirus Profiles configured other than the default, this is a finding.

View the configured Antivirus Profiles; for each protocol decoder (SMTP, IMAP, POP3, FTP, HTTP, SMB).

If the "Action" is anything other than "drop" or "reset-both", this is a finding.

Go to Policies >> Security.

Review each of the configured security policies in turn. For any Security Policy that affects traffic between internal Zones (interzone), view the "Profile" column.

If the "Profile" column does not display the “Antivirus Profile” symbol, this is a finding.'
  desc 'fix', 'To create an Antivirus Profile:
Go to Objects >> Security Profiles >> Antivirus.

Select "Add".

In the "Antivirus Profile" window, complete the required fields.

Complete the "Name" and "Description" fields.

In the "Antivirus" tab, for all Decoders (SMTP, IMAP, POP3, FTP, HTTP, SMB protocols), set the "Action" to "drop" or "reset-both".

Select "OK".

Use the Antivirus Profile in a Security Policy:
Go to Policies >> Security.

Select an existing policy rule or select "Add" to create a new one.

In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.

In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.

Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.

Select "OK" when the confirmation dialog appears.

Use the Antivirus Profile in a Security Policy applied to traffic between internal zones.

Go to Policies >> Security.

Select an existing policy rule or select "Add" to create a new one. 

In the "Actions” tab in the “Profile Setting” section;: 
Iin the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.

In the "Antivirus" field, select the configured Antivirus Profile.

In the "Anti-Spyware" field, select the configured “Anti-Spyware” Profile. 

In the "Vulnerability Protection" field, select the configured “Vulnerability Protection Profile”. 

Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen. 

Select "OK" when the confirmation dialog appears'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7949r358418_chk'
  tag severity: 'medium'
  tag gid: 'V-207695'
  tag rid: 'SV-207695r557390_rule'
  tag stig_id: 'PANW-IP-000026'
  tag gtitle: 'SRG-NET-000249-IDPS-00176'
  tag fix_id: 'F-7949r358419_fix'
  tag 'documentable'
  tag legacy: ['SV-77151', 'V-62661']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

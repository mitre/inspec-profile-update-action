control 'SV-207693' do
  title 'The Palo Alto Networks security platform must detect and deny any prohibited mobile or otherwise malicious code at the enclave boundary.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code.

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors."
  desc 'check', 'Go to Objects >> Security Profiles >> Antivirus.

If no Antivirus Profiles are configured other than the default, this is a finding.

View the configured Antivirus Profiles for each protocol decoder (SMTP, IMAP, POP3, FTP, HTTP, SMB). 

If the "Action" is anything other than "drop" or "reset-both", this is a finding.

Go to Policies >> Security.

Review each of the configured security policies in turn. For any Security Policy that affects traffic from an outside (untrusted) zone, view the "Profile" column. 

If the "Profile" column does not display the “Antivirus Profile” symbol, this is a finding.'
  desc 'fix', 'To create an Antivirus Profile:
Go to Objects >> Security Profiles >> Antivirus.

Select "Add".

In the "Antivirus Profile" window, complete the required fields. 

Complete the "Name" and "Description" fields. 

In the "Antivirus" tab, for all Decoders (SMTP, IMAP, POP3, FTP, HTTP, SMB protocols), set the “Action” to "deny", or “reset-both”.

Select "OK".

Use the Profile in a Security Policy:
Go to Policies >> Security. 

Select an existing policy rule or select "Add" to create a new one.

In the "Actions” tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.

In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.

Select "OK".

Use the Antivirus Profile in a Security Policy applied to traffic from an outside (untrusted) zone.

Go to Policies >> Security.

Select an existing policy rule or select "Add" to create a new one.

In the "Actions” tab in the Profile Setting section:
In the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.

In the "Antivirus" field, select the configured Antivirus Profile. 

In the "Anti-Spyware" field, select the configured Anti-Spyware Profile.

In the "Vulnerability Protection" field, select the configured “Vulnerability Protection Profile”.

Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.

Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7947r768711_chk'
  tag severity: 'medium'
  tag gid: 'V-207693'
  tag rid: 'SV-207693r768712_rule'
  tag stig_id: 'PANW-IP-000020'
  tag gtitle: 'SRG-NET-000229-IDPS-00163'
  tag fix_id: 'F-7947r768710_fix'
  tag 'documentable'
  tag legacy: ['SV-77147', 'V-62657']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end

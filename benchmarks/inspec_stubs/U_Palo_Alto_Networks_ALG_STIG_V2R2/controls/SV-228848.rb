control 'SV-228848' do
  title 'The Palo Alto Networks security platform must drop malicious code upon detection.'
  desc 'Malicious code is designed to compromise information systems; therefore, it must be prevented from being transferred to uninfected hosts.

The Palo Alto Networks security platform allows customized profiles to be used to perform antivirus inspection for traffic between zones. Antivirus, anti-spyware, and vulnerability protection features require a specific license. There is a default Antivirus Profile; the profile inspects all of the listed protocol decoders for viruses, and generates alerts for SMTP, IMAP, and POP3 protocols while dropping for FTP, HTTP, and SMB protocols. However, these default actions cannot be edited and the values for the FTP, HTTP, and SMB protocols do not meet the requirement, so customized profiles must be used.'
  desc 'check', 'Go to Objects >> Security Profiles >> Antivirus
If there are no Antivirus Profiles configured other than the default, this is a finding.

View the configured Antivirus Profiles; for each protocol decoder (SMTP, IMAP, POP3, FTP, HTTP, SMB) if the "Action" is anything other than “drop” or "reset-both", this is a finding.

Go to Policies >> Security.

Review each of the configured security policies in turn. For any Security Policy that allows traffic between Zones (interzone), view the "Profile" column.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.'
  desc 'fix', 'To create an Antivirus Profile:
Go to Objects >> Security Profiles >> Antivirus.

Select "Add".

In the "Antivirus Profile" window, complete the required fields.

Complete the "Name" and "Description" fields.

In the "Antivirus" tab, for all Decoders (SMTP, IMAP, POP3, FTP, HTTP, SMB protocols) set the "Action" to “drop” or "reset-both".

Select "OK".

Use the Antivirus Profile in a Security Policy:
Go to Policies >> Security.

Select an existing policy rule or select "Add" to create a new one.

In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.

In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.

Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.

Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31083r573745_chk'
  tag severity: 'medium'
  tag gid: 'V-228848'
  tag rid: 'SV-228848r559740_rule'
  tag stig_id: 'PANW-AG-000062'
  tag gtitle: 'SRG-NET-000249-ALG-000134'
  tag fix_id: 'F-31060r573746_fix'
  tag 'documentable'
  tag legacy: ['V-62579', 'SV-77069']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

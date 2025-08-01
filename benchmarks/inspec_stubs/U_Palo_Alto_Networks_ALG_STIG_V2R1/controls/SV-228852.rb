control 'SV-228852' do
  title 'The Palo Alto Networks security platform must deny or restrict detected prohibited mobile code.'
  desc 'Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

This applies to mobile code that may originate either internal to or external from the enclave. Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

The Palo Alto Networks security platform allows customized profiles to be used to perform antivirus inspection for traffic between zones. Antivirus, anti-spyware, and vulnerability protection features require a specific license. There is a default Antivirus Profile; the profile inspects all of the listed protocol decoders for viruses, and generates alerts for SMTP, IMAP, and POP3 protocols while denying for FTP, HTTP, and SMB protocols. However, these default actions cannot be edited and the values for the FTP, HTTP, and SMB protocols do not meet the requirement, so customized profiles must be used.'
  desc 'check', 'Go to Objects >> Security Profiles >> Antivirus

If there are no Antivirus Profiles configured other than the default, this is a finding.

View the configured Antivirus Profiles; for each protocol decoder (SMTP, IMAP, POP3, FTP, HTTP, SMB); if the "Action" is anything other than “deny” or "reset-both, this is a finding.

Go to Policies >> Security

Review each of the configured security policies in turn.
For any Security Policy that affects traffic between Zones (interzone), view the "Profile" column.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.'
  desc 'fix', 'To create an Antivirus Profile:
Go to Objects >> Security Profiles >> Antivirus

Select "Add".

In the "Antivirus Profile" window, complete the required fields. 

Complete the "Name" and "Description" fields. 

In the "Antivirus" tab, for all Decoders (SMTP, IMAP, POP3, FTP, HTTP, SMB protocols), set the "Action" to “deny" or "reset-both”.

Select "OK".

Use the Profile in a Security Policy:
Go to Policies >> Security

Select an existing policy rule or select "Add" to create a new one.

In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles. 

In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select Profiles. The window will change to display the different categories of Profiles.

Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.

Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31087r559733_chk'
  tag severity: 'medium'
  tag gid: 'V-228852'
  tag rid: 'SV-228852r559734_rule'
  tag stig_id: 'PANW-AG-000073'
  tag gtitle: 'SRG-NET-000288-ALG-000109'
  tag fix_id: 'F-31064r559732_fix'
  tag 'documentable'
  tag legacy: ['SV-77075', 'V-62585']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end

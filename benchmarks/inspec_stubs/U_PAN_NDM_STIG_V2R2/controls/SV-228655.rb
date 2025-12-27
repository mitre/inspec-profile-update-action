control 'SV-228655' do
  title 'The Palo Alto Networks security platform must prohibit the use of unencrypted protocols for network access to privileged accounts.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Go to Device >> Setup >> Management
View the "Management Interface Settings" pane.
If either Telnet or HTTP is listed in the "Services" field, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Management
In the "Management Interface Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).  In the "Management Interface Settings" window, make sure that HTTP and Telnet are not checked (enabled). 
If they are not checked, select either "OK" or "Cancel".
If either one is checked, select the check box to disable it, then select "OK".
If any changes were made, commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30890r513568_chk'
  tag severity: 'medium'
  tag gid: 'V-228655'
  tag rid: 'SV-228655r513570_rule'
  tag stig_id: 'PANW-NM-000061'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-30867r513569_fix'
  tag 'documentable'
  tag legacy: ['SV-77227', 'V-62737']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

control 'SV-250633' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process. If user names are not unique, there can be no accountability on the system for auditing purposes. Multiple accounts sharing the same name could result in the Denial-of-Service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell. Execute the following command(s): 
# cat /etc/passwd 

If any non-unique user name is found (example: multiple root user name entries), this is a finding. 

Re-enable lock down mode.'
  desc 'fix', 'Change user account names, or delete accounts, so each account has a unique name.  From the vSphere Client/vCenter:  Click on the "Users and Groups" tab.  Click on the "Users" button.  Right click and select "Add". Specify the desired User Name, Password, etc and Click "OK".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54068r798896_chk'
  tag severity: 'medium'
  tag gid: 'V-250633'
  tag rid: 'SV-250633r798898_rule'
  tag stig_id: 'SRG-OS-000121-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54022r798897_fix'
  tag 'documentable'
  tag legacy: ['V-39388', 'SV-51246']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

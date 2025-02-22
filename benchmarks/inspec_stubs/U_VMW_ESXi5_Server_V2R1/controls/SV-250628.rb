control 'SV-250628' do
  title 'All accounts must be assigned unique User Identification Numbers (UIDs).'
  desc "Accounts sharing a UID have full access to each others' files. This has the same effect as sharing a login. There is no way to assure identification, authentication, and accountability because the system sees them as the same user. If the duplicate UID is 0, this gives potential intruders another privileged account to attack."
  desc 'check', 'Disable lock down mode.  Enable the ESXi Shell. Execute the following command(s): # cat /etc/passwd | cut -f 3 -d ":" | sort 

If any duplicate UIDs are found, this is a finding. 

Re-enable lock down mode.'
  desc 'fix', 'Modify user accounts to provide unique UIDs for each account. From the vSphere Client/vCenter:  Click on the "Users and Groups" tab. Click on the "Users" button Right click and select "Add". Specify the desired User Name, Password, etc and Click "OK".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54063r798881_chk'
  tag severity: 'medium'
  tag gid: 'V-250628'
  tag rid: 'SV-250628r798883_rule'
  tag stig_id: 'SRG-OS-000104-ESXI5'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-54017r798882_fix'
  tag 'documentable'
  tag legacy: ['SV-51247', 'V-39389']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

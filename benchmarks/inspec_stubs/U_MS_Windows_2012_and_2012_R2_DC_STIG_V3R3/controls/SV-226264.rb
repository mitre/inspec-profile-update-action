control 'SV-226264' do
  title 'Domain controllers must have a PKI server certificate.'
  desc 'Domain controller must have a server certificate to establish authenticity as part of PKI authentications in the domain.'
  desc 'check', 'Verify the domain controller has a PKI server certificate.

Run "mmc".
Select "Add/Remove Snap-in" from the File menu.
Select "Certificates" in the left pane and click the "Add >" button.
Select "Computer Account", click "Next".
Select the appropriate option for "Select the computer you want this snap-in to manage.", click "Finish".
Click "OK".
Select and expand the Certificates (Local Computer) entry in the left pane.
Select and expand the Personal entry in the left pane.
Select the Certificates entry in the left pane.

If no certificate for the domain controller exists in the right pane, this is a finding.'
  desc 'fix', 'Obtain a server certificate for the domain controller.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27966r476636_chk'
  tag severity: 'medium'
  tag gid: 'V-226264'
  tag rid: 'SV-226264r794523_rule'
  tag stig_id: 'WN12-PK-000005-DC'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-27954r476637_fix'
  tag 'documentable'
  tag legacy: ['V-39334', 'SV-51189']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

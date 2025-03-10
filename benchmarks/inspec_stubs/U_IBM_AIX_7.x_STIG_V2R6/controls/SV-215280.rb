control 'SV-215280' do
  title 'Samba packages must be removed from AIX.'
  desc 'If the smbpasswd file has a mode more permissive than 0600, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Run the following command to check if samba packages are installed on AIX:
# lslpp -l samba*

If the above command shows that samba packages are installed, this is a finding.'
  desc 'fix', 'Run the following command to un-install the samba packages:
# installp -ug samba*'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16478r294291_chk'
  tag severity: 'medium'
  tag gid: 'V-215280'
  tag rid: 'SV-215280r508663_rule'
  tag stig_id: 'AIX7-00-002089'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16476r294292_fix'
  tag 'documentable'
  tag legacy: ['SV-101669', 'V-91571']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

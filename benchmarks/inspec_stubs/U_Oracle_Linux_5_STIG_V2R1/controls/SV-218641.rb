control 'SV-218641' do
  title 'The /etc/smb.conf file must have mode 0644 or less permissive.'
  desc 'If the "smb.conf" file has excessive permissions, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the mode of the smb.conf file.

Procedure:
# ls -lL /etc/samba/smb.conf

If the "smb.conf" has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the smb.conf file to 0644 or less permissive.

Procedure:
# chmod 0644 smb.conf.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20116r556121_chk'
  tag severity: 'medium'
  tag gid: 'V-218641'
  tag rid: 'SV-218641r603259_rule'
  tag stig_id: 'GEN006140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20114r556122_fix'
  tag 'documentable'
  tag legacy: ['V-1028', 'SV-64087']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

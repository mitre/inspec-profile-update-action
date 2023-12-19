control 'SV-1028' do
  title 'The /etc/smb.conf file must have mode 0644 or less permissive.'
  desc 'If the smb.conf file has excessive permissions, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the mode of the smb.conf file.

Procedure:
# find / -name smb.conf
# ls -lL <smb.conf file>

If the smb.conf has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the smb.conf file to 0644 or less permissive.

Procedure:
# chmod 0644 smb.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2048r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1028'
  tag rid: 'SV-1028r2_rule'
  tag stig_id: 'GEN006140'
  tag gtitle: 'GEN006140'
  tag fix_id: 'F-1182r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

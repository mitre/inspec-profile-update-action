control 'SV-35221' do
  title 'The /etc/opt/samba/smb.conf file must have mode 0644 or less permissive.'
  desc 'If the smb.conf file has excessive permissions, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the mode of the smb.conf file.
# ls -lL /etc/opt/samba/smb.conf

If the smb.conf has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the smb.conf file to 0644 or less permissive.
# chmod 0644 /etc/opt/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36697r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1028'
  tag rid: 'SV-35221r1_rule'
  tag stig_id: 'GEN006140'
  tag gtitle: 'GEN006140'
  tag fix_id: 'F-32071r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

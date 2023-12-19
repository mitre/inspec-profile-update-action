control 'SV-46133' do
  title 'The /etc/smb.conf file must have mode 0644 or less permissive.'
  desc 'If the "smb.conf" file has excessive permissions, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the mode of the smb.conf file.

Procedure:
# ls -lL /etc/samba/smb.conf

If the "smb.conf" has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the smb.conf file to 0644 or less permissive.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43392r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1028'
  tag rid: 'SV-46133r1_rule'
  tag stig_id: 'GEN006140'
  tag gtitle: 'GEN006140'
  tag fix_id: 'F-39475r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

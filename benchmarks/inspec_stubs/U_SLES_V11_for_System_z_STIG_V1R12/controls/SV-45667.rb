control 'SV-45667' do
  title 'The at.allow file must have mode 0600 or less permissive.'
  desc 'Permissions more permissive than 0600 (read, write and execute for the owner) may allow unauthorized or malicious access to the at.allow and/or at.deny files.'
  desc 'check', 'Check the mode of the at.allow file.
# ls -lL /etc/at.allow
If the at.allow file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the at.allow file.
# chmod 0600 /etc/at.allow'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43033r1_chk'
  tag severity: 'medium'
  tag gid: 'V-987'
  tag rid: 'SV-45667r1_rule'
  tag stig_id: 'GEN003340'
  tag gtitle: 'GEN003340'
  tag fix_id: 'F-39065r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

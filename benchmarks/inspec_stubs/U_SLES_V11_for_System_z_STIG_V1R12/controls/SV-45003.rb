control 'SV-45003' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/shadow file.
# ls -lL /etc/shadow
If the /etc/shadow file has a mode more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/shadow (or equivalent) file.
# chmod 0400 /etc/shadow'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42407r1_chk'
  tag severity: 'medium'
  tag gid: 'V-800'
  tag rid: 'SV-45003r1_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'GEN001420'
  tag fix_id: 'F-38418r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

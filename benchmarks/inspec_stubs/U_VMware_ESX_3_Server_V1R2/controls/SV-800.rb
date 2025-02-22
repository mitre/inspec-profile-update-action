control 'SV-800' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/shadow file.
# ls -lL /etc/shadow
If the /etc/shadow file has a mode more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/shadow (or equivalent) file.
# chmod <mode> <file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-303r2_chk'
  tag severity: 'medium'
  tag gid: 'V-800'
  tag rid: 'SV-800r2_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'GEN001420'
  tag fix_id: 'F-954r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

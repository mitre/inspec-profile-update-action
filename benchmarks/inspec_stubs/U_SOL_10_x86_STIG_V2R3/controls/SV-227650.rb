control 'SV-227650' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/shadow file.
# ls -lL /etc/shadow
If the /etc/shadow file has a mode more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/shadow (or equivalent) file.
# chmod <mode> <file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29812r488510_chk'
  tag severity: 'medium'
  tag gid: 'V-227650'
  tag rid: 'SV-227650r854479_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29800r488511_fix'
  tag 'documentable'
  tag legacy: ['V-800', 'SV-800']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

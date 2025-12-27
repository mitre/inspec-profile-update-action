control 'SV-226524' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/shadow file.
# ls -lL /etc/shadow
If the /etc/shadow file has a mode more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/shadow (or equivalent) file.
# chmod <mode> <file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28685r482960_chk'
  tag severity: 'medium'
  tag gid: 'V-226524'
  tag rid: 'SV-226524r603265_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-28673r482961_fix'
  tag 'documentable'
  tag legacy: ['V-800', 'SV-800']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

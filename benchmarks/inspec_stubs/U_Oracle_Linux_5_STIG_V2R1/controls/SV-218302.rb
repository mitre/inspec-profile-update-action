control 'SV-218302' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/shadow file.

# ls -lL /etc/shadow

If the /etc/shadow file has a mode more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/shadow (or equivalent) file.

# chmod 0400 /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19777r561695_chk'
  tag severity: 'medium'
  tag gid: 'V-218302'
  tag rid: 'SV-218302r603259_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19775r561696_fix'
  tag 'documentable'
  tag legacy: ['V-800', 'SV-64573']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

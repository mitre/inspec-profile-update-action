control 'SV-38728' do
  title 'The /etc/security/passwd file must have mode 0400.'
  desc 'The /etc/security/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the mode of the /etc/security/passwd file.
Procedure:
# ls -lL /etc/security/passwd
If the mode of this file is more permissive than 0400, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/security/passwd file.
# chmod 0400 /etc/security/passwd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37036r1_chk'
  tag severity: 'medium'
  tag gid: 'V-800'
  tag rid: 'SV-38728r1_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'GEN001420'
  tag fix_id: 'F-32304r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

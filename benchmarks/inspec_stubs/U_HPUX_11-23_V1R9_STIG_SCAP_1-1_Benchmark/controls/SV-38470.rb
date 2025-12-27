control 'SV-38470' do
  title 'The /etc/shadow (or equivalent) file must have mode 0400.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root. The Trusted Mode /tcb tree requires modes more permissive than the shadow file.'
  desc 'fix', 'For Trusted Mode:
# chmod 0555 /tcb
# chmod 0771 /tcb/files /tcb/files/auth
# chmod 0664  /tcb/files/auth/[a-z]/* 

For SMSE:
# chmod 0400 /etc/shadow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-800'
  tag rid: 'SV-38470r2_rule'
  tag stig_id: 'GEN001420'
  tag gtitle: 'GEN001420'
  tag fix_id: 'F-31587r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

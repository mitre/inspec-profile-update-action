control 'SV-38729' do
  title 'The /etc/security/passwd file must not have an extended ACL.'
  desc 'The /etc/security/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Verify the  /etc/security/passwd file has no extended ACL and check if extended permissions are disabled.

Procedure: 
#aclget /etc/security/passwd

If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/security/passwd file 
and disable extended permissions.

#acledit /etc/security/passwd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22340'
  tag rid: 'SV-38729r1_rule'
  tag stig_id: 'GEN001430'
  tag gtitle: 'GEN001430'
  tag fix_id: 'F-32411r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

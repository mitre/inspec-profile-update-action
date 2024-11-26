control 'SV-38724' do
  title 'The /etc/passwd file must not have an extended ACL.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.  The /etc/passwd file contains the list of local system accounts. It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Verify the /etc/passwd file has no extended ACL.

Procedure:
#aclget /etc/passwd 
Check to see if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/passwd file and disable extended permissions.

#acledit /etc/passwd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22334'
  tag rid: 'SV-38724r1_rule'
  tag stig_id: 'GEN001390'
  tag gtitle: 'GEN001390'
  tag fix_id: 'F-32276r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

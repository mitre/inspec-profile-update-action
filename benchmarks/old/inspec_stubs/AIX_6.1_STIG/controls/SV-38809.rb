control 'SV-38809' do
  title 'The alias file must not have an extended ACL.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect e-mail.'
  desc 'check', 'Check the permissions of the /etc/mail/aliases file.

#aclget /etc/mail/aliases 

Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the alias file and disable extended permissions.
  
#acledit /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36882r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22439'
  tag rid: 'SV-38809r1_rule'
  tag stig_id: 'GEN004390'
  tag gtitle: 'GEN004390'
  tag fix_id: 'F-31896r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

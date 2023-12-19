control 'SV-38736' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files for extended ACLs.

Procedure:
#aclget /etc/security/.profile 
#aclget /etc/security/mkuser.sys

Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the skeleton file(s) and disable extended permissions.

#acledit /etc/security/.profile 
#acledit /etc/security/mkuser.sys'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37166r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22357'
  tag rid: 'SV-38736r1_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'GEN001810'
  tag fix_id: 'F-32451r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

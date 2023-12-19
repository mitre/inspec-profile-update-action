control 'SV-38693' do
  title 'The /etc/hosts file must not have an extended ACL.'
  desc 'The /etc/hosts file (or equivalent) configures local host name to IP address mappings that typically take precedence over DNS resolution.  If this file is maliciously modified, it could cause the failure or compromise of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Verify /etc/hosts has no extended ACL.
Check to see if extended permissions are disabled.
Procedure:

#aclget /etc/hosts 
If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/hosts file and disable extended permissions. 

#acledit /etc/hosts'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22326'
  tag rid: 'SV-38693r1_rule'
  tag stig_id: 'GEN001369'
  tag gtitle: 'GEN001369'
  tag fix_id: 'F-32270r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

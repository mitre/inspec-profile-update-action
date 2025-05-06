control 'SV-38972' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the permissions of the /etc/security/ldap/ldap.cfg file.

Procedure:
# aclget /etc/security/ldap/ldap.cfg 
Check to see if extended permissions are enabled. 
If extended permissions are enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/security/ldap/ldap.cfg file. 

# acledit /etc/security/ldap/ldap.cfg 
Disable extended file permissions.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22562'
  tag rid: 'SV-38972r1_rule'
  tag stig_id: 'GEN008120'
  tag gtitle: 'GEN008120'
  tag fix_id: 'F-33181r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

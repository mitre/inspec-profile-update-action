control 'SV-38971' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be group-owned by security, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the ldap.cfg file.

Procedure:
# ls -lL /etc/security/ldap/ldap.cfg

If the file is not group-owned by bin, security, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/security/ldap/ldap.cfg file to security, bin, sys, or system.

Procedure:
# chgrp security /etc/security/ldap/ldap.cfg'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37924r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22561'
  tag rid: 'SV-38971r1_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'GEN008100'
  tag fix_id: 'F-33180r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

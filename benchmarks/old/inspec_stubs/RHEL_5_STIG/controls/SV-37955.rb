control 'SV-37955' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the group owner of the file to root, bin, sys, or system.

Procedure:
# chgrp root /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22561'
  tag rid: 'SV-37955r1_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'GEN008100'
  tag fix_id: 'F-32444r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

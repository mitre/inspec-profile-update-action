control 'SV-37967' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate file.
Procedure:
# grep -i '^tls_cert' /etc/ldap.conf

Check the group ownership.
Procedure:
# ls -lL <certpath>

If the group owner of the file is not root, bin, sys, or system, this is a finding."
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root <certpath>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22568'
  tag rid: 'SV-37967r1_rule'
  tag stig_id: 'GEN008240'
  tag gtitle: 'GEN008240'
  tag fix_id: 'F-32501r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

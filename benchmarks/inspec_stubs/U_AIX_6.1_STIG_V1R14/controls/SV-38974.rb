control 'SV-38974' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Check the group ownership of the SSL key database file.

Determine the location of the SSL key database.
# grep -i '^ldapsslkeyf' /etc/security/ldap/ldap.cfg

Check the group ownership of the SSL key database file.
# ls -lLa <ldap certificate file(s) or directories>

If a certificate file or directory is not group-owned by root, bin, security, sys, or system, this is a finding."
  desc 'fix', 'Change the group ownership of LDAP client SSL certificate  database file to root, security, bin, sys, or system.

Procedure:
# chgrp system < certificate file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22564'
  tag rid: 'SV-38974r1_rule'
  tag stig_id: 'GEN008160'
  tag gtitle: 'GEN008160'
  tag fix_id: 'F-33183r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

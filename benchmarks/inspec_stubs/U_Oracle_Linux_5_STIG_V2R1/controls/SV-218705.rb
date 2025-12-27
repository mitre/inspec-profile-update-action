control 'SV-218705' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20180r556532_chk'
  tag severity: 'medium'
  tag gid: 'V-218705'
  tag rid: 'SV-218705r603259_rule'
  tag stig_id: 'GEN008240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20178r556533_fix'
  tag 'documentable'
  tag legacy: ['V-22568', 'SV-63253']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

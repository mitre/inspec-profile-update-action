control 'SV-218701' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate authority file and/or directory.

# grep -i '^tls_cacert' /etc/ldap.conf

For each file or directory returned, check the group ownership.

# ls -lLd <certpath>

If the group-owner of any file or directory is not root, bin, sys, or system, this is a finding."
  desc 'fix', 'Change the group ownership of the file or directory.

# chgrp root <certpath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20176r556520_chk'
  tag severity: 'medium'
  tag gid: 'V-218701'
  tag rid: 'SV-218701r603259_rule'
  tag stig_id: 'GEN008160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20174r556521_fix'
  tag 'documentable'
  tag legacy: ['V-22564', 'SV-63291']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

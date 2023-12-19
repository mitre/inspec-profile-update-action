control 'SV-46030' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification'
  desc 'check', "Determine the certificate authority file and/or directory.
# grep -i '^tls_cacert' /etc/ldap.conf
For each file or directory returned, check the group ownership.
# ls -lLd <certpath>
If the group-owner of any file or directory is not root, bin, sys, or system, this is a finding."
  desc 'fix', 'Change the group ownership of the file or directory.
# chgrp root <certpath>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22564'
  tag rid: 'SV-46030r1_rule'
  tag stig_id: 'GEN008160'
  tag gtitle: 'GEN008160'
  tag fix_id: 'F-39390r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

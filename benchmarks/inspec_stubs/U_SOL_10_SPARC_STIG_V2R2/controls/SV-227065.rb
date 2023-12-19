control 'SV-227065' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be group-owned by root, bin, or sys.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification'
  desc 'check', "Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify the group ownership of the certificate database files.
# ls -lL /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db
If the group owner of any of the files is not root, bin, or sys, this is a finding."
  desc 'fix', 'Change the group ownership of the certificate database files.
# chgrp root /var/ldap/cert8.db /var/ldap/key3.db /var/ldap/secmod.db'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29227r485570_chk'
  tag severity: 'medium'
  tag gid: 'V-227065'
  tag rid: 'SV-227065r603265_rule'
  tag stig_id: 'GEN008160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29215r485571_fix'
  tag 'documentable'
  tag legacy: ['V-22564', 'SV-39907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-227062' do
  title 'If the system is using LDAP for authentication or account information, the LDAP configuration file must be group-owned by root, bin, or sys.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the files.

Procedure:
# ls -lL /var/ldap/ldap_client_file /var/ldap/ldap_client_cred

If the files are not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the files to root, bin, or sys.

Procedure:
# chgrp root /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29224r485561_chk'
  tag severity: 'medium'
  tag gid: 'V-227062'
  tag rid: 'SV-227062r603265_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29212r485562_fix'
  tag 'documentable'
  tag legacy: ['V-22561', 'SV-39906']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

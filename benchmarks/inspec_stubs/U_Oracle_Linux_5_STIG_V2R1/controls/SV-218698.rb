control 'SV-218698' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/ldap.conf

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the file to root, bin, sys, or system.

Procedure:
# chgrp root /etc/ldap.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20173r556511_chk'
  tag severity: 'medium'
  tag gid: 'V-218698'
  tag rid: 'SV-218698r603259_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20171r556512_fix'
  tag 'documentable'
  tag legacy: ['V-22561', 'SV-63317']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

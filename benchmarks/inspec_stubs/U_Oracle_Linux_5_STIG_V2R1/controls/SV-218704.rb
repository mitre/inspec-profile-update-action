control 'SV-218704' do
  title 'For systems using NSS LDAP, the TLS certificate file must be owned by root.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Its configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate file.
# grep -i '^tls_cert' /etc/ldap.conf
Check the ownership.
# ls -lL <certpath>
If the owner of the file is not root, this is a finding."
  desc 'fix', 'Change the ownership of the file.
# chown root <certpath>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20179r556529_chk'
  tag severity: 'medium'
  tag gid: 'V-218704'
  tag rid: 'SV-218704r603259_rule'
  tag stig_id: 'GEN008220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20177r556530_fix'
  tag 'documentable'
  tag legacy: ['V-22567', 'SV-63257']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

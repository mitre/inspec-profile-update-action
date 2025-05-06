control 'SV-218693' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS connection must require the server provide a certificate with a valid trust path to a trusted CA.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Communication between an LDAP server and a host using LDAP for NSS require authentication.'
  desc 'check', %q(Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify a server certificate is required and verified by the NSS LDAP configuration.
# grep -i '^tls_checkpeer' /etc/ldap.conf
If no line is returned, or the value is not "yes", this is a finding.)
  desc 'fix', 'Edit "/etc/ldap.conf" and add or set the "tls_checkpeer" setting to "yes".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20168r556496_chk'
  tag severity: 'medium'
  tag gid: 'V-218693'
  tag rid: 'SV-218693r603259_rule'
  tag stig_id: 'GEN008020'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-20166r556497_fix'
  tag 'documentable'
  tag legacy: ['V-22557', 'SV-63361']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

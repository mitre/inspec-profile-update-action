control 'SV-218694' do
  title 'If the system is using LDAP for authentication or account information, the system must verify the LDAP servers certificate has not been revoked.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'check', %q(Check if the system is using NSS LDAP.

# grep -v '^#' /etc/nsswitch.conf | grep ldap

If no lines are returned, this vulnerability is not applicable.

Verify the NSS LDAP client is configured to check certificates against a certificate revocation list.

# grep -i '^tls_crlcheck' /etc/ldap.conf

If the setting does not exist, or the value is not "all", this is a finding.)
  desc 'fix', 'Edit "/etc/ldap.conf" and add or set the "tls_crlcheck" setting to "all".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20169r556499_chk'
  tag severity: 'medium'
  tag gid: 'V-218694'
  tag rid: 'SV-218694r603259_rule'
  tag stig_id: 'GEN008040'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-20167r556500_fix'
  tag 'documentable'
  tag legacy: ['V-22558', 'SV-63357']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

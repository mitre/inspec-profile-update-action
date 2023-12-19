control 'SV-215214' do
  title 'If LDAP authentication is required on AIX, SSL must be used between LDAP clients and the LDAP servers to protect the integrity of remote access sessions.'
  desc 'If LDAP authentication is used, SSL must be used between LDAP clients and the LDAP servers to protect the integrity of remote access sessions.'
  desc 'check', 'Run the following command to check if ldap_auth is used:

# grep -iE "^authtype:[[:blank:]]*ldap_auth" /etc/security/ldap/ldap.cfg

If the command has no output, this is Not Applicable.

Run the following command to check if SSL is used:

# grep -iE "^useSSL:[[:blank:]]*yes" /etc/security/ldap/ldap.cfg
useSSL:yes

If the command has no output, this is a finding.'
  desc 'fix', 'Configure the LDAP client on AIX to use the SSL.

Edit /etc/security/ldap/ldap.cfg to have the following line:
useSSL:yes

Restart the client daemon:
# secldapclntd.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16412r294093_chk'
  tag severity: 'medium'
  tag gid: 'V-215214'
  tag rid: 'SV-215214r877394_rule'
  tag stig_id: 'AIX7-00-001104'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-16410r294094_fix'
  tag 'documentable'
  tag legacy: ['V-91461', 'SV-101559']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end

control 'SV-215204' do
  title 'IF LDAP is used, AIX LDAP client must use SSL to authenticate with LDAP server.'
  desc "While LDAP client's authentication type is ldap_auth (server-side authentication), the client sends password to the server in clear text for authentication. SSL must be used in this case."
  desc 'check', 'Run the following command to check if "authtype" is "ldap_auth":
# grep -iE "^authtype:[[:blank:]]*ldap_auth" /etc/security/ldap/ldap.cfg

The above command should yield the following output:
authtype:ldap_auth

Run the following command to check if SSL is not used in the "/etc/security/ldap/ldap.cfg" file:
# grep -iE "^useSSL:[[:blank:]]*yes" /etc/security/ldap/ldap.cfg

The above command should yield the following output:
useSSL:yes

If the first command displays "authtype:ldap_auth" but the second command does not display "useSSL:yes",  this is a finding.'
  desc 'fix', 'Edit the "/etc/security/ldap/ldap.cfg" file to have the following line:
useSSL:yes

Configure the LDAP server and LDAP client to use the SSL according to AIX LDAP documentation.

Restart the client daemon:
# restart-secldapclntd'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16402r294063_chk'
  tag severity: 'high'
  tag gid: 'V-215204'
  tag rid: 'SV-215204r877396_rule'
  tag stig_id: 'AIX7-00-001045'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16400r294064_fix'
  tag 'documentable'
  tag legacy: ['V-91297', 'SV-101395']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

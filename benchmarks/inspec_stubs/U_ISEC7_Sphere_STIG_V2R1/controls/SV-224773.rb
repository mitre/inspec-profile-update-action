control 'SV-224773' do
  title 'The ISEC7 EMM Suite must be configured to leverage the enterprise directory service accounts and groups for ISEC7 EMM Suite server admin identification and authentication.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. If an attacker compromises an account, the entire infrastructure is at risk. Providing automated support functions for the management of accounts will ensure only active accounts will be granted access with the proper authorization levels. These objectives are best achieved by configuring the server to leverage an enterprise authentication mechanism (e.g., Microsoft Active Directory Kerberos).'
  desc 'check', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> LDAP.
Verify that a LDAP entry has been configured to the enterprise.
Select Edit and confirm the Use for Login check box has been selected.
Navigate to Administration >> Configuration >> Settings.
Verify that Log in using (Default) has been set to the enterprise connection.

If a LDAP entry has not been configured to the enterprise or Log in using (Default) has not been set to the enterprise connection, this is a finding.'
  desc 'fix', 'Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> LDAP.
Select Add new LDAP .
Provide the connection information for the enterprise LDAP connection.
Check the box Use for Login.
Navigate to Administration >> Configuration >> Settings.
Set Log in using (Default) to the enterprise connection.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26464r461575_chk'
  tag severity: 'medium'
  tag gid: 'V-224773'
  tag rid: 'SV-224773r505933_rule'
  tag stig_id: 'ISEC-06-002510'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-26452r461576_fix'
  tag 'documentable'
  tag legacy: ['V-97261', 'SV-106375']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

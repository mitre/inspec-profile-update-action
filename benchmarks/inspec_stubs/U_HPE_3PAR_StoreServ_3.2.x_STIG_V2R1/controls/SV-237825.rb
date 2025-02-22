control 'SV-237825' do
  title 'The storage system must only be operated in conjunction with an LDAP server in a trusted environment if an Active Directory server is not available.'
  desc 'Where strong account and password management capabilities are required, the 3PAR system is heavily dependent on its ability to use an LDAP server.

'
  desc 'check', 'Determine if the system is configured for LDAP.

Enter the following command:

cli% showauthparam

If the output indicates an error, this is a finding.

If the resulting output does not include group parameters "groups-dn", "group-obj", or "group-name-attr" then the host is configured to use Active Directory and this requirement is not applicable. 

If the host is using LDAP and the following fields of the output are not configured, this is a finding.

ldap-server <ip address of LDAP server> 
ldap-server-hn <host name of LDAP server>

Next, verify that the LDAP authentication is operational by entering the following command:

cli% checkpassword <username>
password: <Enter the password for username>

If the username and password used in "checkpassword" are known to be valid LDAP credentials, and the following text is NOT displayed at the end of the resulting output, this is a finding.

user <username> is authenticated and authorized

Note: The "checkpassword" command will not display authenticated information even if LDAP is properly configured, if the username and password are not entered correctly.'
  desc 'fix', 'Use this series of commands to configure LDAP.

cli% setauthparam -f ldap-server        <ldap server IP address>
cli% setauthparam -f ldap-server-hn     <fully qualified domain name of ldap server, such as ldapserver.thisdomain.com>
cli% setauthparam -f binding            simple
cli% setauthparam -f ldap-StartTLS      require
cli% setauthparam -f groups-dn          ou=Groups,dc=thisdomain,dc=com
cli% setauthparam -f user-dn-base       ou=People,dc=thisdomain,dc=com
cli% setauthparam -f user-attr          uid
cli% setauthparam -f group-obj          groupofuniquenames
cli% setauthparam -f group-name-attr    cn
cli% setauthparam -f member-attr        uniqueMember
cli% setauthparam -f browse-map         "*"
cli% setauthparam -f edit-map           <customer-assigned name of edit role> <customer-assigned name of "edit" group>
cli% setauthparam -f service-map       <customer-assigned name of service role> <customer-assigned name of "service" group>
cli% setauthparam -f super-map          <customer-assigned name of super role> <customer-assigned name of "super" group>'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41035r647882_chk'
  tag severity: 'high'
  tag gid: 'V-237825'
  tag rid: 'SV-237825r647884_rule'
  tag stig_id: 'HP3P-32-001503'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-40994r647883_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000104-GPOS-00051', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-85125', 'V-70503']
  tag cci: ['CCI-000015', 'CCI-000366', 'CCI-000764']
  tag nist: ['AC-2 (1)', 'CM-6 b', 'IA-2']
end

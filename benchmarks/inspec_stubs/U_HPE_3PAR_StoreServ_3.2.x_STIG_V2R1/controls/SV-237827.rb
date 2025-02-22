control 'SV-237827' do
  title 'The storage system must only be operated in conjunction with an Active Directory server in a trusted environment if an LDAP server is not available.'
  desc 'Where strong account and password management capabilities are required, the 3PAR system is heavily dependent on its ability to use an AD server.

'
  desc 'check', 'Determine if the system is configured for Active Directory (AD). 

Enter the following command:

cli% showauthparam

If the result returns an error, this is a finding.

If the resulting output does include the parameters "groups-dn", "group-obj", or "group-name-attr" then the host is setup for LDAP, this requirement is not applicable.

If the host is setup for Active Directory and these fields in the output are not configured, this is a finding.

ldap-server <ip address of AD server> 
ldap-server-hn <host name of AD server>

Next, verify that the AD authentication is operational by entering the following command:

cli% checkpassword <username>:
password: <Enter the password for username>

If the username and password used in checkpassword are known to be valid AD credentials, and the following text is NOT displayed at the end of the resulting output, this is a finding.

user <username> is authenticated and authorized

Note: The "checkpassword" command will not display authenticated information even if AD is properly configured, if the username and password are not entered correctly.'
  desc 'fix', 'Use this series of commands to configure the host to use Active Directory:

cli% setauthparam -f ldap-server        <AD server IP address>
cli% setauthparam -f binding            simple
cli% setauthparam -f ldap-StartTLS      require
cli% setauthparam -f Kerberos-realm     <Kerberos realm, such as WIN2K12FOREST.THISDOMAIN.COM>
cli% setauthparam -f ldap-server-hn     <fully qualified domain name of AD server, such as adserver.thisdomain.com>
cli% setauthparam -f accounts-dn        CN=Users,DC=win2k12forest,DC=thisdomain,DC=com
cli% setauthparam -f user-dn-base       CN=Users,DC=win2k12forest,DC=thisdomain,DC=com
cli% setauthparam -f user-attr          WIN2K12FOREST\\\\
cli% setauthparam -f account-obj        user
cli% setauthparam -f account-name-attr  sAMAccountName
cli% setauthparam -f memberof-attr      memberOf
cli% setauthparam -f browse-map         "CN=<customer-assigned name of browse role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f edit-map           "CN=<customer-assigned name of edit role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f service-map        "CN=<customer-assigned name of service role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"
cli% setauthparam -f super-map          "CN=<customer-assigned name of super role>,CN=Users,DC=win2k12forest,DC=thisdomain,DC=com"'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41037r647888_chk'
  tag severity: 'high'
  tag gid: 'V-237827'
  tag rid: 'SV-237827r647890_rule'
  tag stig_id: 'HP3P-32-001507'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-40996r647889_fix'
  tag satisfies: ['SRG-OS-000001-GPOS-00001', 'SRG-OS-000104-GPOS-00051', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-85129', 'V-70507']
  tag cci: ['CCI-000015', 'CCI-000366', 'CCI-000764']
  tag nist: ['AC-2 (1)', 'CM-6 b', 'IA-2']
end

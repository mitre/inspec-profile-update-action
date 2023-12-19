control 'SV-254093' do
  title 'Innoslate must use multifactor authentication for network access to privileged and non-privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

'
  desc 'check', '1. Enter the settings.properties file located at C:\\Innoslate4\\apache-tomcat\\webapps\\Innoslate4\\WEB-INF.
2. Find the LDAP fields.
3. Verify LDAP information is correct. If not, this is a finding.

The LDAP Fields should look (not exactly) like this:

"
LDAP_INITIAL_CONTEXT_FACTORY = com.sun.jndi.ldap.LdapCtxFactory
LDAP_PROVIDER_URLS = ldap://providerUrl.com
LDAP_SECURITY_AUTHENTICATION = none
LDAP_SECURITY_PRINCIPAL = CN=Admin Innoslate,CN=Users,DC=Innoslateactive,DC=com
LDAP_SECURITY_CREDENTIALS = password
LDAP_USER_CONTEXT = CN=Users,DC=Innoslateactive,DC=com
LDAP_USER_OBJECT_CLASS = user
LDAP_USER_UID_ATTRIBUTE = sAMAccountName
LDAP_CONNECT_TIMEOUT = 1000
LDAP_READ_TIMEOUT = 5000
LDAP_USER_EMAIL_ATTRIBUTE = mail
LDAP_USER_FIRST_NAME_ATTRIBUTE = givenName
LDAP_USER_LAST_NAME_ATTRIBUTE = sn
LDAP_USER_PHONE_NUMBER_ATTRIBUTE = telephoneNumber
LDAP_USER_COMPANY_ATTRIBUTE = company
LDAP_USER_SEARCH_FILTER = (&(objectClass=user)(sAMAccountName={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
"'
  desc 'fix', '1. Enter settings.properties file.
2. Change the AUTHENTICATION_TYPE  to "CAC".
3. Save.
4. Restart the Innoslate service.'
  impact 0.7
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57578r845253_chk'
  tag severity: 'high'
  tag gid: 'V-254093'
  tag rid: 'SV-254093r845255_rule'
  tag stig_id: 'SPEC-IN-000280'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-57529r845254_fix'
  tag satisfies: ['SRG-APP-000149', 'SRG-APP-000024', 'SRG-APP-000025', 'SRG-APP-000026', 'SRG-APP-000027', 'SRG-APP-000028', 'SRG-APP-000029', 'SRG-APP-000065', 'SRG-APP-000148', 'SRG-APP-000150', 'SRG-APP-000151', 'SRG-APP-000152', 'SRG-APP-000153', 'SRG-APP-000157', 'SRG-APP-000163', 'SRG-APP-000164', 'SRG-APP-000165', 'SRG-APP-000166', 'SRG-APP-000167', 'SRG-APP-000168', 'SRG-APP-000169', 'SRG-APP-000170', 'SRG-APP-000173', 'SRG-APP-000174', 'SRG-APP-000175', 'SRG-APP-000176', 'SRG-APP-000291', 'SRG-APP-000292', 'SRG-APP-000293', 'SRG-APP-000294', 'SRG-APP-000295', 'SRG-APP-000318', 'SRG-APP-000319', 'SRG-APP-000320', 'SRG-APP-000356', 'SRG-APP-000391', 'SRG-APP-000392', 'SRG-APP-000397', 'SRG-APP-000401', 'SRG-APP-000402', 'SRG-APP-000403', 'SRG-APP-000404', 'SRG-APP-000405', 'SRG-APP-000427']
  tag 'documentable'
  tag cci: ['CCI-000185', 'CCI-000186', 'CCI-000194', 'CCI-000195', 'CCI-000198', 'CCI-000199', 'CCI-000765', 'CCI-001619', 'CCI-001683', 'CCI-001684', 'CCI-001685', 'CCI-001686', 'CCI-001844', 'CCI-001953', 'CCI-001954', 'CCI-001991', 'CCI-002009', 'CCI-002010', 'CCI-002011', 'CCI-002014', 'CCI-002041', 'CCI-002130', 'CCI-002132', 'CCI-002145', 'CCI-002361', 'CCI-002470']
  tag nist: ['IA-5 (2) (b) (1)', 'IA-5 (2) (a) (1)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (d)', 'IA-5 (1) (d)', 'IA-2 (1)', 'IA-5 (1) (a)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AU-3 (2)', 'IA-2 (12)', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)', 'IA-8 (1)', 'IA-8 (2)', 'IA-8 (4)', 'IA-5 (1) (f)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (11)', 'AC-12', 'SC-23 (5)']
end

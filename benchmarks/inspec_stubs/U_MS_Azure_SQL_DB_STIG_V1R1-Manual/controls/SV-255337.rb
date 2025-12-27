control 'SV-255337' do
  title 'Azure SQL Database must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).'
  desc 'Nonorganizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Nonorganizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, assets, individuals, and other organizations.'
  desc 'check', 'Review documentation, Azure SQL Database settings, and authentication system settings to determine if nonorganizational users are individually identified and authenticated when logging onto the system. 

If accounts are determined to be shared, determine if individuals are first individually authenticated. Where an application connects to Azure SQL Database using a standard, shared account, ensure that it also captures the individual user identification and passes it to Azure SQL Database. 

If the documentation indicates that this is a public-facing, read-only (from the point of view of public users) database that does not require individual authentication, this is not a finding. 

If nonorganizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Ensure all logins are uniquely identifiable and authenticate all nonorganizational users who log onto the system. This likely would be done via a combination of Azure Active Directory with unique accounts and the Azure SQL Database by ensuring mapping to individual accounts. Verify server documentation to ensure accounts are documented and unique.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59010r871135_chk'
  tag severity: 'medium'
  tag gid: 'V-255337'
  tag rid: 'SV-255337r871137_rule'
  tag stig_id: 'ASQL-00-008800'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-58954r871136_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

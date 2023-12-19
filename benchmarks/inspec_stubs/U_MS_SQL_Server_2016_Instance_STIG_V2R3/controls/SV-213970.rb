control 'SV-213970' do
  title 'SQL Server must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 
 
Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 
 
Accordingly, a risk assessment is used in determining the authentication needs of the organization. 
 
Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', "Review documentation, SQL Server settings, and authentication system settings to determine if non-organizational users are individually identified and authenticated when logging onto the system.  
 
Execute the following query to obtain a list of logins on the SQL Server and ensure all accounts are uniquely identifiable: 
 
SELECT name, type_desc FROM sys.server_principals WHERE type in ('S','U') 
 
If accounts are determined to be shared, determine if individuals are first individually authenticated. Where an application connects to SQL Server using a standard, shared account, ensure that it also captures the individual user identification and passes it to SQL Server. 
 
If the documentation indicates that this is a public-facing, read-only (from the point of view of public users) database that does not require individual authentication, this is not a finding.  
 
If non-organizational users are not uniquely identified and authenticated, this is a finding."
  desc 'fix', 'Ensure all logins are uniquely identifiable and authenticate all non-organizational users who log onto the system. This likely would be done via a combination of the operating system with unique accounts and the SQL Server by ensuring mapping to individual accounts. Verify server documentation to ensure accounts are documented and unique.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15187r313693_chk'
  tag severity: 'medium'
  tag gid: 'V-213970'
  tag rid: 'SV-213970r617437_rule'
  tag stig_id: 'SQL6-D0-008800'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-15185r313694_fix'
  tag 'documentable'
  tag legacy: ['SV-93907', 'V-79201']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

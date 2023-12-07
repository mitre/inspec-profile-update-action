control 'SV-224175' do
  title 'The DBMS must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.

With Postgres, all database users are uniquely identified. To discriminate non-organizational users from organizational users, applications often create and utilize one or more tables to record additional information about the users, including their organizational affiliations. Another approach that may be used is to create and assign database roles corresponding to the different organizations. The EDB Postgres Advanced Server session audit log tagging feature can also be used to log additional information about the user associated with a database session such as organizational affiliation. The session audit tagging feature uses the edb_audit_tag parameter. Typically, this parameter would be set on a session by session basis via the application that connects to the EDB Postgres Advanced Server database.'
  desc 'check', 'Review documentation, EDB Postgres Advanced Server settings, and authentication system settings to determine if non-organizational users are individually identified and authenticated when logging onto the system.

EDB Postgres Advanced Server uniquely identifies and authenticates Postgres users through the use of DBMS roles.

To list the user and group roles in an EDB Postgres Advanced Server instance, execute the following command in psql as the enterprisedb user:

 \\du

If accounts are determined to be shared, determine if individuals are first individually authenticated. Where an application connects to EDB Postgres Advanced Server using a standard, shared account, ensure it also captures the individual user identification, and passes it to EDB Postgres Advanced Server.

If the EDB session audit log tagging feature is being used to capture individual user identification and organizational affiliation, review the EDB audit log to verify that the information documented as being required is logged to the "audit_tag" field. If the required information is not logged, this is a finding.

If the documentation indicates that this is a public-facing, read-only (from the point of view of public users) database that does not require individual authentication, this is not a finding.

If non-organizational users are not uniquely identified and authenticated, this is a finding.'
  desc 'fix', 'Ensure all logins are uniquely identifiable and authenticate all non-organizational users who log onto the system. This likely would be done via a combination of application, operating system, and EDB Postgres Advanced Server configuration settings. Verify server documentation to ensure accounts are documented and unique.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25848r495543_chk'
  tag severity: 'medium'
  tag gid: 'V-224175'
  tag rid: 'SV-224175r508023_rule'
  tag stig_id: 'EP11-00-005000'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-25836r495544_fix'
  tag 'documentable'
  tag legacy: ['V-100375', 'SV-109479']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

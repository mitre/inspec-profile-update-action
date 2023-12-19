control 'SV-251230' do
  title 'Redis Enterprise DBMS must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the nation.'
  desc 'check', 'Redis Enterprise databases can be configured and set to deny by default posture. Access is granted when the database is configured and can be granted by admins at a later time. Verify in the database configuration that the default user is disabled. This would force non-organizational users to authenticate with a username and password similar to any organizationally defined user. 

In web UI:
1. Log in to Redis Enterprise as an admin user.
2. Select the Database tab.
3. Select the Configuration subtab.
4. Confirm "Default database access" reads "nopass" and is "Inactive".

If default database access is active and there is no password set, this is a finding.'
  desc 'fix', 'When adding user access to the database, either during initial creation or at a later time, admins must establish a unique username and password for all users and the default user account must be disabled.

In web UI:
1. Log in to Redis Enterprise as an admin user.
2. Select the Database tab.
3. Select the Configuration subtab.
4. Select "Edit".
5. Ensure that "Default database access" is unchecked.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54665r804878_chk'
  tag severity: 'medium'
  tag gid: 'V-251230'
  tag rid: 'SV-251230r804880_rule'
  tag stig_id: 'RD6X-00-009600'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-54619r804879_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

control 'SV-252163' do
  title 'MongoDB must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', %q(MongoDB grants access to data and commands through role-based authorization and provides built-in roles that provide the different levels of access commonly needed in a database system. Additionally, one may create user-defined roles. 

Check a user's role to ensure correct privileges for the function:

Prereq: To view a user's roles, you must have the viewUser privilege. 

Connect to MongoDB.

For each database in the system, identify the user's roles for the database:

use database
db.getUser(%username%)

The server will return a document with the user's roles.

View a roles' privileges:

Prereq: To view a user's roles, you must have the viewUser privilege. 

For each database, identify the privileges granted by a role:

use database
db.getRole( "read", { showPrivileges: true } )

The server will return a document with the privileges and inheritedPrivileges arrays. The privileges returned document lists the privileges directly specified by the role and excludes those privileges inherited from other roles. The inheritedPrivileges returned document lists all privileges granted by this role, both directly specified and inherited. If the role does not inherit from other roles, the two fields are the same.

If a user has a role with inappropriate privileges, this is a finding.)
  desc 'fix', "Administrators using MongoDB should document the appropriate privileges for various roles appropriate to the application.

Prereq: To view a user's roles, must have the viewUser privilege. 

Connect to MongoDB.

For each database, identify the user's roles for the database. 

use database
db.getUser(%username%)

The server will return a document with the user's roles.

To revoke a user's role from a database use the db.revokeRolesFromUser() method.

To grant a role to a user use the db.grantRolesToUser(...) method."
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55619r817010_chk'
  tag severity: 'medium'
  tag gid: 'V-252163'
  tag rid: 'SV-252163r817011_rule'
  tag stig_id: 'MD4X-00-003400'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-55569r813870_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

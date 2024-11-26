control 'SV-252140' do
  title 'MongoDB must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations).

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.

Accordingly, a risk assessment is used in determining the authentication needs of the organization.

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', "MongoDB grants access to data and commands through role-based authorization and provides built-in roles that provide the different levels of access commonly needed in a database system. Additionally, user-defined roles can be created. 

Check a user's role to ensure correct privileges for the function:

Run the following command to get a list of all the databases in the system:

 show dbs

For each database in the system, identify the user's roles for the database:

 use database
 db.getUsers()

The server will return a document with the all users in the data and their associated roles.

View a roles' privileges: 

For each database, identify the privileges granted by a role:

 use database
 db.getRole( %rolename%, { showPrivileges: true } )

The server will return a document with the privileges and inheritedPrivileges arrays. 

The privileges returned document lists the privileges directly specified by the role and excludes those privileges inherited from other roles. 

The inheritedPrivileges returned document lists all privileges granted by this role, both directly specified and inherited. If the role does not inherit from other roles, the two fields are the same.

If a user has a role with inappropriate privileges, this is a finding."
  desc 'fix', "Administrators using MongoDB should document the appropriate privileges for various roles appropriate to the application.

For each database, identify the user's roles for the database. 

 use database
 db.getUser(%username%)

The server will return a document with the user's roles.

To revoke a user's role from a database, run the following:  

 db.revokeRolesFromUser( %username%, [ roles ], { writeConcern } )

To grant a role to a user run the following:
 
 db.grantRolesToUser( %username%, [ roles ], { writeConcern } )"
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55596r813800_chk'
  tag severity: 'medium'
  tag gid: 'V-252140'
  tag rid: 'SV-252140r813802_rule'
  tag stig_id: 'MD4X-00-000700'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-55546r813801_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end

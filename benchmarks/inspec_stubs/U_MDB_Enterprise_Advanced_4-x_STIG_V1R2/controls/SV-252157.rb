control 'SV-252157' do
  title 'MongoDB must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.'
  desc 'check', 'For each database in the system, run the following command:

 use database
 db.getUsers()

Ensure each user identified is a member of an appropriate organization that can access the database.

Alternatively, if LDAP/AD is being used for authentication/authorization, the mongoldap tool can be used to verify user account access.

If a user is found not be a member of an appropriate organization that can access the database, this is a finding.

Verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following:

security:
  authorization: enabled
 
If this parameter is not present, this is a finding.'
  desc 'fix', 'For any user not a member of an appropriate organization and has access to a database in the system, run the following command:

 use database
 db.dropUser(%username%, {w: "majority", wtimeout: 5000})

If the %MongoDB configuration file% (default location: /etc/mongod.conf) does not contain

security: 
  authorization: enabled

Edit the %MongoDB configuration file%, add these parameters, stop/start (restart) any mongod or mongos process using this %MongoDB configuration file%.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55613r813851_chk'
  tag severity: 'medium'
  tag gid: 'V-252157'
  tag rid: 'SV-252157r813853_rule'
  tag stig_id: 'MD4X-00-002800'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-55563r813852_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

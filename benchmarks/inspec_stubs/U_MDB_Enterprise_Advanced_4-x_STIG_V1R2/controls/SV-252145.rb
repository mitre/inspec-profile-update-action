control 'SV-252145' do
  title 'MongoDB must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects.

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level.

The policy is bound by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

'
  desc 'check', 'Review the MongoDB Configuration file (default location: /etc/mongod.conf).

If the file does not contain the following entry, this is a finding. 

security:
    authorization: enabled'
  desc 'fix', 'Enable authentication for MongoDB by following the instructions here: https://docs.mongodb.com/v4.4/tutorial/enable-authentication/

Create an administrative user in MongoDB:

 use admin
 db.createUser(
  {
    user: "UserAdmin",
    pwd: passwordPrompt(), // or cleartext password
    roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
  }
)

Enable authorization by adding the following entry to the %MongoDB configuration file%:

security:
    authorization: enabled

Restart the MongoDB service from the OS.

 sudo service mongod restart

The createUser and createRole MongoDB commands will be used to add the required users and roles per organizational or site-specific documentation.

https://docs.mongodb.com/v4.4/reference/command/createUser/
https://docs.mongodb.com/v4.4/reference/command/createRole/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55601r813815_chk'
  tag severity: 'medium'
  tag gid: 'V-252145'
  tag rid: 'SV-252145r855504_rule'
  tag stig_id: 'MD4X-00-001200'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-55551r813816_fix'
  tag satisfies: ['SRG-APP-000328-DB-000301', 'SRG-APP-000340-DB-000304']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end

control 'SV-251187' do
  title 'Redis Enterprise DBMS must enforce access control lists, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Review the system documentation to determine what organizationally defined Access Control permissions should be in place. Compare these settings with the settings on the actual DB.

1. Log in to Redis Enterprise.
2. Navigate to the access controls tab >> redis acls
3. Review ACLs for appropriate rules. If ACL rules are not defined as appropriate in system documentation, this is a finding.
4. Review roles.
5. Verify that each role is assigned an appropriate ACL. If a role is not assigned an appropriate ACL, this is a finding.
6. Review users.
7. Verify that each user is assigned a role. If a user is not assigned an appropriate role, this is a finding.

If any user accounts implicitly gain “Full Access” through the user/role/ACL relationship and are not authorized, this is a finding.'
  desc 'fix', 'To configure a Redis ACL rule that can be assigned to a user role:
1. Navigate to access control >> redis acls.
2. Edit an existing Redis ACL by hovering over a Redis ACL and clicking "Edit".
3. Create a new Redis ACL by clicking "Add".
4. Enter a descriptive name for the Redis ACL. This will be used to reference the ACL rule to the role.
5. Define the ACL rule.
6. Click "Save".

Assign ACLs to roles and roles to users as appropriate.

For more information: 
https://docs.redislabs.com/latest/rs/security/passwords-users-roles/'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54622r804749_chk'
  tag severity: 'medium'
  tag gid: 'V-251187'
  tag rid: 'SV-251187r855595_rule'
  tag stig_id: 'RD6X-00-000950'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-54576r804750_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

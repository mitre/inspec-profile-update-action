control 'SV-96613' do
  title 'MongoDB must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects.

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level.

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

'
  desc 'check', 'Review the system documentation to obtain the definition of the database/DBMS functionality considered privileged in the context of the system in question.

If any functionality considered privileged has access privileges granted to non-privileged users, this is a finding.'
  desc 'fix', 'Revoke any roles with unnecessary privileges to privileged functionality by executing the revoke command as documented here: 
https://docs.mongodb.com/v3.4/reference/method/db.revokeRolesFromUser/

Revoke any unnecessary privileges from any roles by executing the revoke command as document here: 
https://docs.mongodb.com/v3.4/reference/method/db.revokePrivilegesFromRole/

If a new role with associated privileges needs to be created, follow the documentation here:
https://docs.mongodb.com/v3.4/reference/command/createRole/'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81899'
  tag rid: 'SV-96613r1_rule'
  tag stig_id: 'MD3X-00-000570'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-88749r1_fix'
  tag satisfies: ['SRG-APP-000328-DB-000301', 'SRG-APP-000340-DB-000304']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end

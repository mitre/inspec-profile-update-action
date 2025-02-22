control 'SV-206585' do
  title 'The DBMS must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled table permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Review system documentation to identify the required discretionary access control (DAC).

Review the security configuration of the database and DBMS. If applicable, review the security configuration of the application(s) using the database.

If the discretionary access control defined in the documentation is not implemented in the security configuration, this is a finding.'
  desc 'fix', "Implement the organization's DAC policy in the security configuration of the database and DBMS, and, if applicable, the security configuration of the application(s) using the database."
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6845r291423_chk'
  tag severity: 'medium'
  tag gid: 'V-206585'
  tag rid: 'SV-206585r617447_rule'
  tag stig_id: 'SRG-APP-000328-DB-000301'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-6845r291424_fix'
  tag 'documentable'
  tag legacy: ['SV-72449', 'V-58019']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

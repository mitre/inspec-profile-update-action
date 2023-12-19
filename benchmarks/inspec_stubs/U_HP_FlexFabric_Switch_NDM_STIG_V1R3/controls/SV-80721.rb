control 'SV-80721' do
  title 'If the HP FlexFabric Switch uses discretionary access control, the HP FlexFabric Switch must enforce organization-defined discretionary access control policies over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual network administrators are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

The discretionary access control policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Check the HP FlexFabric Switch to determine if organization-defined discretionary access control policies are enforced over defined subjects and objects.

[HP] display local-user

local-user test
 authorization-attribute user-role network-operator

If organization-defined discretionary access control policies are not enforced over defined subjects and objects, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce organization-defined discretionary access control policies over defined subjects and objects. Below is an example of a test user being assigned pre-defined user-role network-operator:

[HP] local-user test
[HP-luser-test] authorization-attribute user-role network-operator'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66231'
  tag rid: 'SV-80721r1_rule'
  tag stig_id: 'HFFS-ND-000088'
  tag gtitle: 'SRG-APP-000328-NDM-000286'
  tag fix_id: 'F-72307r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

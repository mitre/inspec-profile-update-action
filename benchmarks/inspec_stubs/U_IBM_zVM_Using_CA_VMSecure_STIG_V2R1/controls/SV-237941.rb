control 'SV-237941' do
  title 'CA VM:Secure product MANAGE command must be restricted to system administrators.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Examine “AUTHORIZ CONFIG” file.

If the “MANAGE” command is only granted to system administrators, this is not a finding.'
  desc 'fix', 'Include the “GRANT” statement for the “MANAGE” command to restrict to system administrators only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41151r649661_chk'
  tag severity: 'medium'
  tag gid: 'V-237941'
  tag rid: 'SV-237941r649663_rule'
  tag stig_id: 'IBMZ-VM-000980'
  tag gtitle: 'SRG-OS-000312-GPOS-00124'
  tag fix_id: 'F-41110r649662_fix'
  tag 'documentable'
  tag legacy: ['SV-93635', 'V-78929']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

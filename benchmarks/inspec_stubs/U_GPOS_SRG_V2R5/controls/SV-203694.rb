control 'SV-203694' do
  title 'The operating system must allow operating system admins to change security attributes on users, the operating system, or the operating systems components.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', "Verify the operating system allows operating system admins to change security attributes on users, the operating system, or the operating system's components. If it does not, this is a finding."
  desc 'fix', "Configure the operating system to allow operating system admins to change security attributes on users, the operating system, or the operating system's components."
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3819r375029_chk'
  tag severity: 'medium'
  tag gid: 'V-203694'
  tag rid: 'SV-203694r851760_rule'
  tag stig_id: 'SRG-OS-000312-GPOS-00124'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-3819r375030_fix'
  tag 'documentable'
  tag legacy: ['V-57229', 'SV-71489']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

control 'SV-246928' do
  title 'ONTAP must enforce organization-defined DAC policies.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual network administrators are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

The discretionary access control policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Use "security login show -vserver <vserver_name> -role vsadmin" to see users with DAC over a vserver domain within ONTAP.

If ONTAP does not enforce organization-defined DAC policies, this is a finding.'
  desc 'fix', 'Configure new users with DAC in ONTAP for a specific vserver domain with “security login create -vserver <vserver_name> -role vsadmin -user-or-group-name <user_name> -application ssh -authentication-method password".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50360r769114_chk'
  tag severity: 'medium'
  tag gid: 'V-246928'
  tag rid: 'SV-246928r769116_rule'
  tag stig_id: 'NAOT-AC-000007'
  tag gtitle: 'SRG-APP-000328-NDM-000286'
  tag fix_id: 'F-50314r769115_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

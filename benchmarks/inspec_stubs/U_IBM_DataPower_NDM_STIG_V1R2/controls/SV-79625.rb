control 'SV-79625' do
  title 'If the DataPower Gateway uses discretionary access control, the DataPower Gateway must enforce organization-defined discretionary access control policies over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual network administrators are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

The discretionary access control policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Navigate to the DataPower Gateway RBM settings at Administration >> Access >> RBM, Authentication tab using the web interface. Verify that each role is authenticated according to appropriate control policy. If they are not, this is a finding.'
  desc 'fix', 'As the DataPower administrator, configure the DataPower Gateway to enforce role-based access control policy over defined subjects and objects. In the WebGUI, go to Administration >> Access >> RBM Settings. On the Authentication tab, select the approved authentication server. Enter the information required for an authenticated user to access defined subjects and objects.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65135'
  tag rid: 'SV-79625r1_rule'
  tag stig_id: 'WSDP-NM-000088'
  tag gtitle: 'SRG-APP-000328-NDM-000286'
  tag fix_id: 'F-71075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

control 'SV-93399' do
  title 'The Tanium Server directory must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to Program Files >> Tanium.

Right-click on the Tanium Server folder.
Select "Properties".
Select the "Security" tab.
Click on the "Advanced" button.
Validate the owner of the Tanium Server folder is the service account [Tanium service account].
Validate the [Tanium service account] has full permissions to the Tanium Server folder.
Validate the [Tanium Admins] group has full permissions to the Tanium Server folder.
Validate users have no permissions to the Tanium Server folder.

If any accounts other than the [Tanium service account] and the [Tanium Admins] group have any permission to the Tanium Server folder, this is a finding.

If the [Tanium service account] is not the owner of the Tanium Server folder, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to Program Files >> Tanium.

Right-click on the "Tanium Server" folder.
Select "Properties".
Select the "Security" tab.
Click on the "Advanced" button.
Disable folder inheritance.
Change the owner of the directory to the service account [Tanium service account].
Remove User permissions.
Give [Tanium service account] full permissions.
Give [Tanium Admins] group full permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78693'
  tag rid: 'SV-93399r1_rule'
  tag stig_id: 'TANS-SV-000024'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-85429r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

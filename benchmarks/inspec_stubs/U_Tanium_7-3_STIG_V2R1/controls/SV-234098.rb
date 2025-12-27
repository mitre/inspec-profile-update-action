control 'SV-234098' do
  title 'The Tanium Server Logs and TDL_Logs directories must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Access the Tanium Server interactively.

Log on to the server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on the "Logs" folder.

Select "Properties".

Click on the "Security" tab.

Click on the "Advanced" button.

Validate the owner of the directory is the [Tanium service account].

Validate the [Tanium service account] privileges is only account with modify permissions on the directory.

Validate the [Tanium Administrators] group has full permissions on the directory.

Right-click on the "TDL_Logs" folder.

Select "Properties".

Click on the "Security" tab.

Click on the "Advanced" button. 

Validate the owner of the directory is the [Tanium service account].

Validate the [Tanium service account] privileges is the only account with modify permissions on the directory.

Validate the [Tanium Administrators] group has full permissions on the directory.

If any of the specified permissions are not set as required, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on to their server with an account that has administrative privileges.

Open an Explorer window.

Navigate to Program Files >> Tanium >> Tanium Server.

Right-click on the "Logs" folder.

Select "Properties".

Click on the "Security" tab.

Click on the "Advanced" button.

Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce [Tanium service account] privileges to modify permissions on the directory.

Ensure [Tanium Admins] group has full permissions on the directory.

Right-click on the "TDL_Logs" folder.

Select "Properties".

Click on the "Security" tab.

Click on the "Advanced" button.

Disable folder inheritance.

Change/verify the owner of the directory to the [Tanium service account].

Reduce [Tanium service account] privileges to modify permissions on the directory.

Ensure [Tanium Admins] group has full permissions on the directory.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37283r610794_chk'
  tag severity: 'medium'
  tag gid: 'V-234098'
  tag rid: 'SV-234098r612749_rule'
  tag stig_id: 'TANS-SV-000027'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-37248r610795_fix'
  tag 'documentable'
  tag legacy: ['SV-102269', 'V-92167']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

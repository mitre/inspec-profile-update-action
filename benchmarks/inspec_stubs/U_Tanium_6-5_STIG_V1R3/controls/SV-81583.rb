control 'SV-81583' do
  title 'The Tanium Server http directory and sub-directories must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the C:\\Program Files\\Tanium folder\\Tanium Server\\http folder.

Right-click on the \\http folder, select “Properties”.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read-Only permissions.

Right-click on the \\legacy folder.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate the System has Read-Only permissions.
Validate the [Tanium service account] has Read-Only permissions.
Navigate into the \\legacy folder.
Validate the \\legacy\\index.html.bak file does not exist.

Right-click on the \\libraries folder.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read-Only permissions.
Validate the [Tanium service account] has Read-Only permissions.

Right-click on the \\taniumjs folder.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read-Only permissions.
Validate the [Tanium service account] has Read-Only permissions.

Right-click on the \\tux folder.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read-Only permissions.
Validate the [Tanium service account] has Read Only permissions.

Right-click on the \\tux-console folder.
Select the “Security” tab, click on the “Advanced” button.
Validate the owner of the directory is the [Tanium service account].
Validate System has Read-Only permissions.
Validate the [Tanium service account] has Read-Only permissions.

If any of the above permissions are not configured correctly, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Open an Explorer window.

Navigate to the C:\\Program Files\\Tanium folder\\Tanium Server\\http folder.

Right-click on the \\http folder, select “Properties”.
Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Reduce System to Read-Only permissions.

Right-click on the \\legacy folder.
Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Delete index.html.bak.
Reduce System to Read-Only permissions. 
Reduce [Tanium service account] to Read-Only permissions.
Right-click on the \\libraries folder.

Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Reduce System to Read-Only permissions.
Reduce [Tanium service account] to Read-Only permissions.

Right-click on the \\taniumjs folder.
Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Reduce System to Read-Only permissions.
Reduce [Tanium service account] to Read-Only permissions.

Right-click on the \\tux folder.
Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Reduce System to Read-Only permissions.
Reduce [Tanium service account] to Read-Only permissions.

Right-click on the \\tux-console folder.
Select the “Security” tab, click on the “Advanced” button.
Disable folder inheritance.
Change/verify the owner of the directory to the [Tanium service account].
Reduce System to Read-Only permissions.
Reduce [Tanium service account] to Read-Only permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67093'
  tag rid: 'SV-81583r1_rule'
  tag stig_id: 'TANS-SV-000025'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-73193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

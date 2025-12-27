control 'SV-81585' do
  title 'The permissions on the Tanium Server registry keys must be restricted to only the Tanium service account.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Access the Tanium Server interactively. 

Log on with an account with administrative privileges to the server.

Run regedit as Administrator.

Navigate to HKLM\\Local_Machine\\Software\\Wow6432Node.

Right-click on \\Tanium, select “Properties”.
Click on the “Security” tab, “Advanced” button.
Validate the [Tanium service account] is only account with full permissions.
Validate the User accounts do not have any permissions.

If any other account has full permissions and/or the User account has any permissions, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Run regedit as Administrator.

Navigate to HKLM\\Local_Machine\\Software\\Wow6432Node.

Right-click on \\Tanium, select “Properties”.
Click on the “Security” tab, “Advanced” button.
Provide the [Tanium service account] with full permissions.
Reduce permissions for any other accounts with full permissions.
Remove permissions for User accounts.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67731r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67095'
  tag rid: 'SV-81585r1_rule'
  tag stig_id: 'TANS-SV-000026'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-73195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

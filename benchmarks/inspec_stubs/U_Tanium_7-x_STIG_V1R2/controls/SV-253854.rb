control 'SV-253854' do
  title 'The permissions on the Tanium Server registry keys must be restricted to only the Tanium service account and the [Tanium Admins] group.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When DAC policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of DAC require identity-based access control, that limitation is not required for this use of DAC.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Right-click "Tanium Server".

6. Select "Permissions".

7. Click the "Security" tab.

8. Click the "Advanced" button.

- Validate the [Tanium service account] has full permissions.
- Validate the [Tanium Admins] group has full permissions.
- Validate the SYSTEM account has full permissions.
- Validate the User accounts do not have any permissions.

If any other account has full permissions and/or the User account has any permissions, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Run regedit as Administrator.

4. Navigate to HKEY_LOCAL_MACHINE >> SOFTWARE >> Wow6432Node >> Tanium >> Tanium Server.

5. Right-click "Tanium Server".

6. Select "Properties".

7. Click the "Security" tab.

8. Click the "Advanced" button.

9. Provide the [Tanium service account] with full permissions.

10. Provide the [Tanium Admins] group with full permissions.

11. Reduce permissions for any other accounts with full permissions.

12. Remove permissions for User accounts.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57306r842588_chk'
  tag severity: 'medium'
  tag gid: 'V-253854'
  tag rid: 'SV-253854r850167_rule'
  tag stig_id: 'TANS-SV-000026'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-57257r842589_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

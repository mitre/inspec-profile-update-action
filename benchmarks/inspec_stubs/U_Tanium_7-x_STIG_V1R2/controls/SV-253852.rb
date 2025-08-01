control 'SV-253852' do
  title 'The Tanium Server directory must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When DAC policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of DAC require identity-based access control, that limitation is not required for this use of DAC.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium.

5. Right-click the "Tanium Server" folder.

6. Select "Properties".

7. Select the "Security" tab.

8. Click the "Advanced" button. 

- Validate the owner of the "Tanium Server" folder is the service account [Tanium service account].
- Validate the [Tanium service account] has full permissions to the "Tanium Server" folder.
- Validate the [Tanium Admins] group has full permissions to the "Tanium Server" folder.
- Validate Users have no permissions to the "Tanium Server" folder.

If any accounts other than the [Tanium service account] and the [Tanium Admins] group have any permission to the "Tanium Server" folder, this is a finding.

If the [Tanium service account] is not the owner of the "Tanium Server" folder, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium.

5. Right-click the "Tanium Server" folder.

6. Select "Properties".

7. Select the "Security" tab.

8. Click the "Advanced" button.

9. Disable folder inheritance.

10. Change the owner of the directory to the service account [Tanium service account].

11. Remove User permissions.

12. Give [Tanium service account] full permissions.

13. Give [Tanium Admins] group full permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57304r842582_chk'
  tag severity: 'medium'
  tag gid: 'V-253852'
  tag rid: 'SV-253852r850167_rule'
  tag stig_id: 'TANS-SV-000024'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-57255r842583_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

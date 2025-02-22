control 'SV-253855' do
  title 'The Tanium Server Logs and TDL_Logs directories must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of DAC require identity-based access control, that limitation is not required for this use of DAC.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Logs" folder.

6. Select "Properties".

7. Click the "Security" tab.

8. Click the "Advanced" button.

- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium service account] privileges is the only account with modify permissions on the directory.
- Validate the [Tanium Administrators] group has full permissions on the directory.

9. Right-click the "TDL_Logs" folder.

10. Select "Properties".

11. Click the "Security" tab.

12. Click the "Advanced" button. 

- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium service account] privileges is the only account with modify permissions on the directory.
- Validate the [Tanium Administrators] group has full permissions on the directory.

If any of the specified permissions are not set as required, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Logs" folder.

6. Select "Properties".

7. Click the "Security" tab.

8. Click the "Advanced" button.

9. Disable folder inheritance.

10. Change/verify the owner of the directory to the [Tanium service account].

11. Reduce [Tanium service account] privileges to modify permissions on the directory.

12. Ensure [Tanium Admins] group has full permissions on the directory.

13. Right-click the "TDL_Logs" folder.

14. Select "Properties".

15. Click the "Security" tab.

16. Click the "Advanced" button.

17. Disable folder inheritance.

18. Change/verify the owner of the directory to the [Tanium service account].

19. Reduce [Tanium service account] privileges to modify permissions on the directory.

20. Ensure [Tanium Admins] group has full permissions on the directory.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57307r842591_chk'
  tag severity: 'medium'
  tag gid: 'V-253855'
  tag rid: 'SV-253855r850167_rule'
  tag stig_id: 'TANS-SV-000027'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-57258r842592_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

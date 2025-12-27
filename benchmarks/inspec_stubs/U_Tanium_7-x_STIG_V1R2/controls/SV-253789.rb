control 'SV-253789' do
  title 'The Tanium application must reveal error messages only to the information system security officer (ISSO), information system security manager (ISSM), and system administrator (SA).'
  desc "Only authorized personnel must be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the application. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open a File Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Logs" folder.

6. Select "Properties".

7. Select the "Security" tab.

8. Click the "Advanced" button.

- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium service account] is the only account with modify permissions on the directory.
- Validate the [Tanium Administrators] group has full permissions on the directory.

9. Right-click the "TDL_Logs" folder.

10. Select "Properties".

11. Select the "Security" tab.

12. Click the "Advanced" button. 

- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium service account] privileges is the only account with modify permissions on the directory.
- Validate the [Tanium Administrators] group has full permissions on the directory.

If any of the specified permissions are not set as required, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open a File Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Logs" folder.

6. Select "Properties".

7. Select the "Security" tab.

8. Click the "Advanced" button.

9. Disable folder inheritance.

10. Change/verify the owner of the directory to the [Tanium service account].

11. Reduce [Tanium service account] privileges to modify permissions on the directory.

12. Ensure [Tanium Admins] group has full permissions on the directory.

13. Right-click the "TDL_Logs" folder.

14. Select "Properties".

15. Select the "Security" tab.

16. Click the "Advanced" button.

17. Disable folder inheritance.

18. Change/verify the owner of the directory to the [Tanium service account].

19. Reduce [Tanium service account] privileges to modify permissions on the directory.

20. Ensure [Tanium Admins] group has full permissions on the directory.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57241r842393_chk'
  tag severity: 'medium'
  tag gid: 'V-253789'
  tag rid: 'SV-253789r842395_rule'
  tag stig_id: 'TANS-00-001190'
  tag gtitle: 'SRG-APP-000267'
  tag fix_id: 'F-57192r842394_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

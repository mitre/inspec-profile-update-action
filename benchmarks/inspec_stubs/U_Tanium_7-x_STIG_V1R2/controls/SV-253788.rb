control 'SV-253788' do
  title 'The Tanium application must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.'
  desc 'Any application providing too much information in error messages risks compromising the data and security of the application and system. The structure and content of error messages must be carefully considered by the organization and development team. 

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, Social Security numbers, and credit card numbers.'
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
- Validate the [Tanium service account] is the only account with modify permissions on the directory.
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
  tag check_id: 'C-57240r842390_chk'
  tag severity: 'medium'
  tag gid: 'V-253788'
  tag rid: 'SV-253788r842392_rule'
  tag stig_id: 'TANS-00-001185'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-57191r842391_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

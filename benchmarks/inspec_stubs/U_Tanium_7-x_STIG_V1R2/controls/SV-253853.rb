control 'SV-253853' do
  title 'The Tanium Server http directory and subdirectories must be restricted with appropriate permissions.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When DAC policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. 

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. 

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of DAC require identity-based access control, that limitation is not required for this use of DAC.'
  desc 'check', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Tanium Server\\http" folder.

6. Select "Properties".

7. Select the "Security" tab.

8. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium Admins] group has full permissions.
- Validate System has Read-Only permissions.

9. Right-click the "Tanium Server\\http\\libraries" folder.

10. Select the "Security" tab.

11. Click the "Advanced" button. 

- Validate Folder Inheritance is disabled. 
- Validate the owner of the directory is the [Tanium service account]. 
- Validate System has Read-Only permissions. 
- Validate the [Tanium service account] has Read-Only permissions. 
- Validate the [Tanium Admins] group has full permissions.

12. Right-click the "Tanium Server\\http\\taniumjs" folder.

13. Select the "Security" tab.

14. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate System has "Read-Only" permissions.
- Validate the [Tanium service account] has "Read-Only" permissions.
- Validate the [Tanium Admins] group has full permissions.

15. Right-click the "Tanium Server\\http\\tux" folder.

16. Select the "Security" tab.

17. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate System has "Read-Only" permissions.
- Validate the [Tanium service account] has "Read Only" permissions.
- Validate the [Tanium Admins] group has full permissions.

18. Right-click the "Tanium Server\\http\\tux-console" folder.

19. Select the "Security" tab.

20. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate System has "Read-Only" permissions.
- Validate the [Tanium service account] has "Read-Only" permissions.
- Validate the [Tanium Admins] group has full permissions.

21. Right-click the "Tanium Server\\Logs" folder.

22. Select "Properties".

23. Select the "Security" tab.

24. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium Service Account] has only "Modify" permissions.
- Validate the [Tanium Admins] group has full permissions.

25. Right-click the "Tanium Server\\TDL_Logs" folder.

26. Select "Properties".

27. Select the "Security" tab.

28. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate the [Tanium Service Account] has only "Modify" permissions.
- Validate the [Tanium Admins] group has full permissions.

29. Right-click the "Tanium Server\\Certs" folder.

30. Select "Properties".

31. Select the "Security" tab.

32. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate System has "Read-Only" permissions.
- Validate the [Tanium Admins] group has full permissions.

33. Navigate to Tanium Server >> Certs.

34. For the following files, verify System and [Tanium Service Account] have "Read-Only" permissions:

installedcacert.crt
installed-server.crt
installed-server.key
SOAPServer.crt
SOAPServer.key

35. Right-click the "Tanium Server\\content_public_keys" folder.

36. Select "Properties".

37. Select the "Security" tab.

38. Click the "Advanced" button.

- Validate Folder Inheritance is disabled.
- Validate the owner of the directory is the [Tanium service account].
- Validate System has "Read-Only" permissions.
- Validate the [Tanium Service Account] has "Read-Only" permissions.
- Validate the [Tanium Admins] group has full permissions.

If any of the above permissions are not configured correctly, this is a finding.'
  desc 'fix', '1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Open an Explorer window.

4. Navigate to Program Files >> Tanium >> Tanium Server.

5. Right-click the "Tanium Server\\http folder.

6. Select "Properties". 

7. Select the "Security" tab.

8. Click the "Advanced" button.

9. Verify/Disable folder inheritance.

10. Change/verify the owner of the directory to the [Tanium service account].

11. Change/verify the [Tanium Admins] group has full permissions.

12. Reduce System to "Read-Only" permissions.

13. Right-click the "Tanium Server\\http\\libraries" folder.

14. Select the "Security" tab.

15. Click the "Advanced" button.

16. Verify/disable folder inheritance.

17. Change/verify the owner of the directory to the [Tanium service account].

18. Reduce System to "Read-Only" permissions.

19. Reduce [Tanium service account] to "Read-Only" permissions.

20. Change/verify the [Tanium Admins] group has full permissions.

21. Right-click the "Tanium Server\\http\\taniumjs" folder.

22. Select the "Security" tab.

23. Click the "Advanced" button.

24. Verify/disable folder inheritance.

25. Change/verify the owner of the directory to the [Tanium service account].

26. Reduce System to "Read-Only" permissions.

27. Reduce [Tanium service account] to "Read-Only" permissions.

28. Change/verify the [Tanium Admins] group has full permissions.

29. Right-click the "Tanium Server\\http\\tux" folder.

30. Select the "Security" tab.

31. Click the "Advanced" button.

32. Verify/disable folder inheritance.

33. Change/verify the owner of the directory to the [Tanium service account].

34. Reduce System to "Read-Only" permissions.

35. Reduce [Tanium service account] to "Read-Only" permissions.

36. Change/verify the [Tanium Admins] group has full permissions.

37. Right-click the "Tanium Server\\http\\tux-console" folder.

38. Select the "Security" tab.

39. Click the "Advanced" button.

40. Verify/disable folder inheritance.

41. Change/verify the owner of the directory to the [Tanium service account].

42. Reduce System to "Read-Only" permissions.

43. Reduce [Tanium service account] to "Read-Only" permissions.

44. Change/verify the [Tanium Admins] group has full permissions.

45. Right-click the "Tanium Server\\Logs" folder.

46. Select the "Security" tab.

47. Click the "Advanced" button.

48. Verify/disable folder inheritance.

49. Change/verify the owner of the directory to the [Tanium service account].

50. Reduce [Tanium service account] to "Modify" permissions.

51. Change/verify the [Tanium Admins] group has full permissions.

52. Right-click the "Tanium Server\\http\\TDL_Logs" folder.

53. Select the "Security" tab.

54. Click the "Advanced" button.

55. Verify/disable folder inheritance.

56. Change/verify the owner of the directory to the [Tanium service account].

57. Reduce [Tanium service account] to "Modify" permissions.

58. Change/verify the [Tanium Admins] group has full permissions.

59. Right-click the "Tanium Server\\Certs" folder.

60. Select the "Security" tab.

61. Click the "Advanced" button.

62. Verify/disable folder inheritance.

63. Change/verify the owner of the directory to the [Tanium service account].

64. Reduce System to "Read-Only" permissions.

65. Change/verify the [Tanium Admins] group has full permissions.

66. Navigate to Tanium Server >> Certs.

67. For the following files, verify/reduce System and [Tanium Service Account] to "Read-Only" permissions:

installedcacert.crt
installed-server.crt
installed-server.key
SOAPServer.crt
SOAPServer.key

68. Right-click the "Tanium Server\\content_public_keys" folder.

69. Select the "Security" tab.

70. Click the "Advanced" button.

71. Verify/disable folder inheritance.

72. Change/verify the owner of the directory to the [Tanium service account].

73. Reduce System to "Read-Only" permissions - apply to child objects.

74. Reduce [Tanium service account] to "Read-Only" permissions - apply to child objects.

75. Change/verify the [Tanium Admins] group has full permissions.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57305r842585_chk'
  tag severity: 'medium'
  tag gid: 'V-253853'
  tag rid: 'SV-253853r850167_rule'
  tag stig_id: 'TANS-SV-000025'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-57256r842586_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

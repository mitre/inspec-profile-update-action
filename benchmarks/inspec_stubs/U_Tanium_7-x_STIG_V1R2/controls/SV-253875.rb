control 'SV-253875' do
  title 'The Tanium Application, SQL, and Module servers must all be configured to communicate using TLS 1.2 Strict Only.'
  desc 'Disabling feedback to senders when there is a failure in protocol validation format prevents adversaries from obtaining information that would otherwise be unavailable.'
  desc 'check', %q(1. Access the Tanium Servers (Application, SQL and Module) interactively.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing "regedit".

4. Press "Enter".

5. Confirm the following settings are in place:
a) Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 2.0 >> Client.

Name: DisabledByDefault
Type: REG_DWORD
Data: 0x0000001 (hex)

If the value for "DisabledByDefault" is not set to "1" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

Name: Enabled
Type: REG_DWORD
Data: 0x00000000 (hex)

If the value for "Enabled" is not set to "0" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

b) Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 2.0 >> Server.

Name: DisabledByDefault
Type: REG_DWORD
Data: 0x0000001 (hex)

If the value for "DisabledByDefault" is not set to "1" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

Name: Enabled
Type: REG_DWORD
Data: 0x00000000 (hex)

If the value for "Enabled" is not set to "0" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

c) Repeat the steps above for SSL 3.0, TLS 1.0, and TLS 1.1.

d) Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> TLS 1.2 >> Client.

Name: DisabledByDefault
Type: REG_DWORD
Data: 0x0000000 (hex)

If the value for "DisabledByDefault" is not set to "0" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

Name: Enabled
Type: REG_DWORD
Data: 0x00000001 (hex)

If the value for "Enabled" is not set to "1" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

e) Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 2.0 >> Server.

Name: DisabledByDefault
Type: REG_DWORD
Data: 0x0000000 (hex)

If the value for "DisabledByDefault" is not set to "0" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.

Name: Enabled
Type: REG_DWORD
Data: 0x00000001 (hex)

If the value for "Enabled" is not set to "1" and "Type" is not configured to "REG_DWORD" or does not exist, this is a finding.)
  desc 'fix', %q(1. Access the Tanium Server.

2. Log on to the server with an account that has administrative privileges.

3. Access the server's registry by typing "regedit".

4. Press "Enter".

5. Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 2.0 >> Client.

6. Right-click in the right window pane.

7. Select: New >> DWORD (32-bit) Value.

8. In the "Name" field, enter "DisabledByDefault".

9. Press "Enter".

10. Right-click the newly created "Name".

11. Select "Modify...".

12. Enter "1" in "Value data:" and ensure that under "Base", the "Hexadecimal" radio button is selected.

13. Click "OK".

14. Right-click in the right window pane.

15. Select: New >> DWORD (32-bit) Value.

16. In the "Name" field, enter "Enabled".

17. Press "Enter".

18. Right-click the newly created "Name".

19. Select "Modify...".

20. Leave default value of "0" in "Value data:".

21. Ensure that under "Base", the "Hexadecimal" radio button is selected.

22. Click "OK".

23. Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> SSL 2.0 >> Server.

24. Right-click in the right window pane.

25. Select: New >> DWORD (32-bit) Value.

26. In the "Name" field, enter "DisabledByDefault".

27. Press "Enter".

28. Right-click the newly created "Name".

29. Select "Modify...".

30. Enter "1" in "Value data:" and ensure that under "Base", the "Hexadecimal" radio button is selected.

31. Click "OK".

32. Right-click in the right window pane.

33. Select: New >> DWORD (32-bit) Value.

34. In the "Name" field, enter "Enabled".

35. Press "Enter".

36. Right-click the newly created "Name".

37. Select "Modify...".

38. Leave default value of "0" in "Value data:".

39. Ensure that under "Base", the "Hexadecimal" radio button is selected.

40. Click "OK".

41. Repeat the above steps for SSL 3.0, TLS 1.0, and TLS 1.1.

42. Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> TLS 1.2 >> Client.

43. Right-click in the right window pane.

44. Select: New >> DWORD (32-bit) Value.

45. In the "Name" field, enter "DisabledByDefault".

46. Press "Enter".

47. Right-click the newly created "Name".

48. Select "Modify...".

49. Enter "0" in "Value data:" and ensure that under "Base", the "Hexadecimal" radio button is selected.

50. Click "OK".

51. Right-click in the right window pane.

52. Select: New >> DWORD (32-bit) Value.

53. In the "Name" field, enter "Enabled".

54. Press "Enter".

55. Right-click the newly created "Name".

56. Select "Modify...".

57. Leave default value of "1" in "Value data:".

58. Ensure that under "Base", the "Hexadecimal" radio button is selected.

59. Click "OK".

60. Navigate to: HKEY_LOCAL_MACHINE >> SYSTEM >> CurrentControlSet >> Control >> SecurityProviders >> SCHANNEL >> Protocols >> TLS 1.2 >> Server.

61. Right-click in the right window pane.

62. Select: New >> DWORD (32-bit) Value.

63. In the "Name" field, enter "DisabledByDefault".

64. Press "Enter".

65. Right-click the newly created "Name".

66. Select "Modify...".

67. Enter "0" in "Value data:" and ensure that under "Base", the "Hexadecimal" radio button is selected.

68. Click "OK".

69. Right-click in the right window pane.

70. Select: New >> DWORD (32-bit) Value.

71. In the "Name" field, enter "Enabled".

72. Press "Enter".

73. Right-click the newly created "Name".

74. Select "Modify...".

75. Leave default value of "1" in "Value data:".

76. Ensure that under "Base", the "Hexadecimal" radio button is selected.

77. Click "OK".)
  impact 0.7
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57327r842651_chk'
  tag severity: 'high'
  tag gid: 'V-253875'
  tag rid: 'SV-253875r850269_rule'
  tag stig_id: 'TANS-SV-000070'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-57278r842652_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

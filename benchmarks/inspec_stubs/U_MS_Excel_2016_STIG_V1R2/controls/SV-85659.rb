control 'SV-85659' do
  title 'WEBSERVICE functions must be disabled.'
  desc %q(This policy setting controls how Excel will warn users when WEBSERVICE functions are present. If you enable this policy setting, you can choose from three options for determining how the specified applications will warn the user about WEBSERVICE functions:- Disable all with notification:  The application displays the Trust Bar for all WEBSERVICE functions. This option enforces the default configuration in Office.- Disable all without notification: The application disables all WEBSERVICE functions and does not notify users.- Enable all WEBSERVICE functions (not recommended):  The application enables all WEBSERVICE functions and does not notify users. This option can significantly reduce security by allowing information disclosure to third party web services. If you disable this policy setting, the 'Disable all with notification' will be the default setting. If you do not configure this policy setting, when users open workbooks that contain WEBSERVICE functions, Excel will open the files with the WEBSERVICE functions disabled and display the Trust Bar with a warning that WEBSERVICE functions are present and have been disabled. Users can inspect and edit the files if appropriate, but cannot use any disabled functionality until they enable it by clicking "Enable Content" on the Trust Bar.  If the user clicks "Enable Content," then the document is added as a trusted document.)
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> "WEBSERVICE Function Notification Settings" is set to "Disabled".   The option 'Enabled: Disable all with notification' is also an acceptable value.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\software\policies\Microsoft\office\16.0\excel\security 

Criteria: If the value webservicefunctionwarnings does not exist,  this is not a finding.   If the registry key exists and is set to REG_DWORD = 1, this is also an acceptable value.   If the value is REG_DWORD = 0 or 2, then this is a finding.)
  desc 'fix', 'Set policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> "WEBSERVICE Function Notification Settings" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71463r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71035'
  tag rid: 'SV-85659r1_rule'
  tag stig_id: 'DTOO418'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77367r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end

control 'SV-53841' do
  title 'WEBSERVICE functions must be disabled.'
  desc 'The WEBSERVICE function option, when used in an Excel spreadsheet, returns data from a web service on the Internet or Intranet. If allowed to be used, security is significantly reduced by allowing information disclosure to third party web services and could potentially introduce malicious content to the local network. The WEBSERVICE function must be disabled in Excel and configured to notify user if a WEBSERVICE function is present in an Excel spreadsheet.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> " WEBSERVICE Function Notification Settings" is set to "Enabled: Disable all with notifications".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\excel\\security 

Criteria: If the value webservicefunctionwarnings is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> " WEBSERVICE Function Notification Settings" is set to "Enabled: Disable all with notifications".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47896r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41344'
  tag rid: 'SV-53841r1_rule'
  tag stig_id: 'DTOO418'
  tag gtitle: 'DTOO418 - Disable WEBSERVICE functions'
  tag fix_id: 'F-46744r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end

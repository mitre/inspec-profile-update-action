control 'SV-87399' do
  title 'Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone.'
  desc 'This policy setting determines whether users can run the Tabular Data Control (TDC) ActiveX control, based on security zone. By default, the TDC ActiveX Control is disabled in the Internet and Restricted Sites security zones. If you enable this policy setting, users will not be able to run the TDC ActiveX control from all sites in the specified zone.'
  desc 'check', 'Note: Only applies to Windows 10 version 1607 and higher and Windows Server 2016 systems. For other Windows versions, this check is Not Applicable. 

In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Panel >> Security Page >> Internet Zone, verify "Allow only approved domains to use the TDC ActiveX control" is “Enabled”. 

In the Options window, verify the “Only allow approved domains to use the TDC ActiveX control" drop-down box is set to “Enable”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3 

Criteria: 

If the value "120c" is REG_DWORD = “3”, this is not a finding.'
  desc 'fix', 'In the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Internet Explorer >> Internet Control Pane >> Security Page >> Internet Zone, set the "Allow only approved domains to use the TDC ActiveX control" to “Enabled”. 

In the Options window, select "Enable" from the “Only allow approved domains to use the TDC ActiveX control" drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 11'
  tag check_id: 'C-72909r7_chk'
  tag severity: 'medium'
  tag gid: 'V-72761'
  tag rid: 'SV-87399r2_rule'
  tag stig_id: 'DTBI1115-IE11'
  tag gtitle: 'DTBI1115-IE11-Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Interne'
  tag fix_id: 'F-79171r6_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

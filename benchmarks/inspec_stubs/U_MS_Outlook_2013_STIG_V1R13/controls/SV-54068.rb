control 'SV-54068' do
  title 'The use of the weather bar in Outlook must be disabled'
  desc 'The Weather Bar in Outlook displays weather conditions and forecast for a geographic location. By default, Outlook uses weather data provided by MSN Weather. The Weather Bar supports third-party weather data web services that follow a defined protocol to communicate with Outlook. As long as a third-party weather data service supports this protocol, users can choose that weather data service to provide weather data in the Weather Bar. Since the Weather Bar communicates to external, commercial weather sites, enabling it introduces the possibility of connections to malicious sites that could download malware into the environment.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> "Disable Weather Bar" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\outlook\\options\\calendar

Criteria: If the value disableweather is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> "Disable Weather Bar" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48008r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41492'
  tag rid: 'SV-54068r1_rule'
  tag stig_id: 'DTOO424'
  tag gtitle: 'DTOO424 - Disable weather bar in Outlook'
  tag fix_id: 'F-46948r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

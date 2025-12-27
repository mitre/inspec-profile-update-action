control 'SV-221575' do
  title 'Metrics reporting to Google must be disabled.'
  desc "Enables anonymous reporting of usage and crash-related data about Google Chrome to Google and prevents users from changing this setting. If you enable this setting, anonymous reporting of usage and crash-related data is sent to Google. A crash report could contain sensitive information from the computer's memory. If you disable this setting, anonymous reporting of usage and crash-related data is never sent to Google. If you enable or disable this setting, users cannot change or override this setting in Google Chrome. If this policy is left not set the setting will be what the user chose upon installation / first run."
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy 
 2. If MetricsReportingEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, then this is a finding.

Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the MetricsReportingEnabled value name does not exist or its value data is not set to 0, then this is a finding.

Note: This policy will only display in the chrome://policy tab on domain joined systems. On standalone systems, the policy will not display.'
  desc 'fix', 'Windows group policy:
   1. Open the group policy editor tool with gpedit.msc   
   2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
    Policy Name: Enable reporting of usage and crash-related data
    Policy State: Disabled
    Policy Value: N/A'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23290r415852_chk'
  tag severity: 'medium'
  tag gid: 'V-221575'
  tag rid: 'SV-221575r615937_rule'
  tag stig_id: 'DTBC-0026'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-23279r415853_fix'
  tag 'documentable'
  tag legacy: ['SV-57605', 'V-44771']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

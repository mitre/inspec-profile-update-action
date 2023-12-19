control 'SV-243372' do
  title 'McAfee VirusScan On Delivery Email Scanner Properties must be configured to record scanning activity in a log file.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Reports tab, locate the "Log file" label. Ensure "Enable activity logging and accept the default location for the log file or specify a new location" is selected. 

Criteria:  If the option "Enable activity logging and accept the default location for the log file or specify a new location" is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions

Criteria:  If the value bLogToFile is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties. 

Under the Reports tab, locate the "Log file" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location." option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46647r722453_chk'
  tag severity: 'medium'
  tag gid: 'V-243372'
  tag rid: 'SV-243372r722455_rule'
  tag stig_id: 'DTAM035'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-46604r722454_fix'
  tag 'documentable'
  tag legacy: ['V-6602', 'SV-56399']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

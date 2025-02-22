control 'SV-55187' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies must be configured to record scanning activity in a log file.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Reports tab, locate the "Log to file:" label. Ensure that "Enable activity logging and accept the default location for the log file or specify a new location" is selected. 

Criteria:  If the option "Enable activity logging and accept the default location for the log file or specify a new location" is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions

Criteria:  If the value bLogToFile is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Reports tab, locate the "Log to file:" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48790r4_chk'
  tag severity: 'medium'
  tag gid: 'V-6596'
  tag rid: 'SV-55187r2_rule'
  tag stig_id: 'DTAM035'
  tag gtitle: 'DTAM035-McAfee VirusScan log to file email'
  tag fix_id: 'F-48041r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

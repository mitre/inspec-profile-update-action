control 'SV-55188' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies log file size must be restricted and be configured to be at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. 

Under the Reports tab, locate the "Log file size" label. 

Criteria:  If the "Limit the size of log file" is checked and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions

Criteria:  If both the value of bLimitSize is 1 and the value of dwMaxLogSizeMB is at least decimal (10), this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Delivery Email Scan Policies. Under the Reports tab, locate the "Log file size:" label.  Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of 10MB or more. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48791r4_chk'
  tag severity: 'medium'
  tag gid: 'V-6597'
  tag rid: 'SV-55188r2_rule'
  tag stig_id: 'DTAM036'
  tag gtitle: 'DTAM036-McAfee VirusScan limit log size email'
  tag fix_id: 'F-48042r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end

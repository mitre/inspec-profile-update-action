control 'SV-56393' do
  title 'McAfee VirusScan On-Delivery Email Scanner log file size must be restricted and be configured to be at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted. If the data in the log file exceeds the file size set, the oldest 20 percent of the entries are deleted and new data is appended to the file so although the file size is restricted, it must also be large enough to retain forensic value.'
  desc 'check', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties.

Under the Reports tab, locate the "Log file size" label. 

Criteria:  If the "Limit the size of log file" is checked and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner\\Outlook\\OnDelivery\\ReportOptions

Criteria:   If both the value of bLimitSize is 1 and the value of dwMaxLogSizeMB is at least decimal (10), this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select the On-Delivery Email Scanner Option, right-click, and select Properties. 

Under the Reports tab, locate the "Log file" label.  

Select the "Limit the size of log file" option. For the "Maximum log file size:" select a value of at least 10MB. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49310r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6597'
  tag rid: 'SV-56393r2_rule'
  tag stig_id: 'DTAM036'
  tag gtitle: 'DTAM036-McAfee VirusScan limit log size email'
  tag fix_id: 'F-49115r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end

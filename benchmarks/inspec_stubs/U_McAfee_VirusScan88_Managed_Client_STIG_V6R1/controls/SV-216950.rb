control 'SV-216950' do
  title 'McAfee VirusScan Access Protection log file size must be restricted and be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'Note: If DTAM161 "McAfee VirusScan Access Protection Policies must be configured to enable access protection" has been marked as "Not Applicable", this check is not applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Access Protection Policies. Under the Reports tab, locate the "Log file size:" label. 

Ensure the "Limit the size of log file" option is selected. Ensure the "Maximum log file size" is 10MB or more.

Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is 10MB or more, this is not a finding. 


On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria: If the value of bLimitSize is 1 and dwMaxLogSizeMB is configured to Decimal (10) or higher, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Access Protection Policies. Under the Reports tab, locate the "Log file size:" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of at least 10MB or more. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18180r309579_chk'
  tag severity: 'medium'
  tag gid: 'V-216950'
  tag rid: 'SV-216950r395805_rule'
  tag stig_id: 'DTAM140'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-18178r309580_fix'
  tag 'documentable'
  tag legacy: ['SV-55246', 'V-42518']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end

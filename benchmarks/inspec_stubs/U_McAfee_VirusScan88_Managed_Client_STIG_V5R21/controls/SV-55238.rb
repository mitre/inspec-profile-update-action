control 'SV-55238' do
  title 'McAfee VirusScan Buffer Overflow Protection Policies log file size must be restricted and be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'NOTE:  Buffer Overflow Protection is not installed on 64-bit systems and would be Not Applicable to 64-bit systems. 

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed"; this check would be Not Applicable.
 
From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Buffer Overflow Protection Policies. Under the Reports tab, locate the "Log file size:" label. Ensure the "Limit the size of log file" option is selected. Ensure the "Maximum log file size" is at least 10MB.

Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\McAfee\\ (32-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of bLimitSize_Ent is 1 and dwMaxLogSizeMB_Ent is configured to Decimal (10) or higher, this is not a finding. If the bLimitSize_Ent is 0 or if dwMaxLogSizeMB_Ent is less than Decimal (10), this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Buffer Overflow Protection Policies. Under the Reports tab, locate the "Log file size" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of 10MB or more. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48828r3_chk'
  tag severity: 'medium'
  tag gid: 'V-14661'
  tag rid: 'SV-55238r1_rule'
  tag stig_id: 'DTAM134'
  tag gtitle: 'DTAM134-McAfee VirusScan log size limitation'
  tag fix_id: 'F-48093r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

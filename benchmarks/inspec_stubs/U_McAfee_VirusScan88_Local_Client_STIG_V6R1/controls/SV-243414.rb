control 'SV-243414' do
  title 'McAfee VirusScan Access Protection Reports log file size must be restricted and be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'Note: If DTAM161 "McAfee VirusScan Access Protection Policies must be configured to enable access protection" has been marked as "Not Applicable", this check is not applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log File:" label. 
Ensure the "Limit the size of log file" option is selected. Ensure the "Maximum log file size" is 10MB or more.

Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is 10MB or more, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria: If the value of bLimitSize is 1 and dwMaxLogSizeMB is configured to Decimal (10) or higher, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log File" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of 10MB or more. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46689r722579_chk'
  tag severity: 'medium'
  tag gid: 'V-243414'
  tag rid: 'SV-243414r722581_rule'
  tag stig_id: 'DTAM140'
  tag gtitle: 'SRG-APP-000109'
  tag fix_id: 'F-46646r722580_fix'
  tag 'documentable'
  tag legacy: ['V-42564', 'SV-55292']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end

control 'SV-56418' do
  title 'McAfee VirusScan Buffer Overflow Protection Reports Settings log file size must be restricted, but be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'OTE:  Buffer Overflow Protection is not installed on 64-bit systems; this check would be Not Applicable to 64-bit systems.

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed";  this check would be Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log File" label. Ensure the "Limit the size of log file" option is selected. Ensure the "Maximum log file size" is at least 10MB.
Criteria:  If the "Limit the size of log file" option is selected and the "Maximum log file size:" is at least 10MB, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\McAfee\\ (32-bit)

SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of bLimitSize_Ent is 1 and dwMaxLogSizeMB_Ent is configured to Decimal (10) or higher, this is not a finding. If the bLogToFile_Ent is 0 or if dwMaxLogSizeMB_Ent is less than Decimal (10), this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log file" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of 10MB or more. 

Click OK to Save..'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49345r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14661'
  tag rid: 'SV-56418r1_rule'
  tag stig_id: 'DTAM134'
  tag gtitle: 'DTAM134-McAfee VirusScan log size limitation'
  tag fix_id: 'F-49149r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

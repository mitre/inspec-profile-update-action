control 'SV-56421' do
  title 'McAfee VirusScan Buffer Overflow Protection Reports Settings must be configured to log buffer overflow protection scan activity.'
  desc 'Log management is essential to ensuring computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'NOTE:  Buffer Overflow Protection is not installed on 64-bit systems; this check would be Not Applicable to 64-bit systems. 

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed"; this check would be Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log file" label. Ensure the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected.

Criteria:  If the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value bLogToFile_Ent is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log file" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49344r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14660'
  tag rid: 'SV-56421r1_rule'
  tag stig_id: 'DTAM133'
  tag gtitle: 'DTAM133-McAfee VirusScan buffer overflow log'
  tag fix_id: 'F-49148r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

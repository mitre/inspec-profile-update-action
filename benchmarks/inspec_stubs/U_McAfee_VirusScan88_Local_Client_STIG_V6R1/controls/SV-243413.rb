control 'SV-243413' do
  title 'McAfee VirusScan Access Protection Reports settings must be configured to record scanning activity in a log file.'
  desc 'Log management is essential to ensuring computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'Note: If DTAM161 "McAfee VirusScan Access Protection Policies must be configured to enable access protection" has been marked as "Not Applicable", this requirement is not applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log File" label. Ensure the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected.

Criteria:  If the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of bLogToFile is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Reports tab, locate the "Log file" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46688r722576_chk'
  tag severity: 'medium'
  tag gid: 'V-243413'
  tag rid: 'SV-243413r722578_rule'
  tag stig_id: 'DTAM139'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-46645r722577_fix'
  tag 'documentable'
  tag legacy: ['V-42563', 'SV-55291']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

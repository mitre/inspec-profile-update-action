control 'SV-243387' do
  title 'McAfee VirusScan On-Demand scan must be configured to record scanning activity in a log file.'
  desc 'Log management is essential to ensuring computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "Log File" label. Ensure the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected.

Criteria:  If "Enable activity logging and accept the default location for the log file or specify a new location" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the bLogToFile does not have a value of 1, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "Log file" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. 


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46662r722498_chk'
  tag severity: 'medium'
  tag gid: 'V-243387'
  tag rid: 'SV-243387r722500_rule'
  tag stig_id: 'DTAM059'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46619r722499_fix'
  tag 'documentable'
  tag legacy: ['V-6470', 'SV-56370']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

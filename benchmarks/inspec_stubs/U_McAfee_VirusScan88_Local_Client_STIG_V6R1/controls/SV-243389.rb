control 'SV-243389' do
  title 'McAfee VirusScan On-Demand scan must be configured to log any failure to scan encrypted files.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Ensure the "Failure to scan encrypted files" option is selected.

Criteria:  If the "Failure to scan encrypted files" option is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the value bLogScanEncryptFail is not set to 1, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Reports tab, locate the "What to log in addition to scanning activity:" label. Select the "Failure to scan encrypted files" option. 

Click OK to Save'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46664r722504_chk'
  tag severity: 'medium'
  tag gid: 'V-243389'
  tag rid: 'SV-243389r722506_rule'
  tag stig_id: 'DTAM063'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46621r722505_fix'
  tag 'documentable'
  tag legacy: ['V-6475', 'SV-56372']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

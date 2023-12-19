control 'SV-56426' do
  title 'McAfee VirusScan On-Demand scan must be scheduled to be executed at least on a weekly basis.'
  desc 'Antivirus software is the mostly commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Click on the Schedule button.
Under the Task tab, under "Schedule Settings", ensure the "Enable (scheduled task runs at a specified time)" option is selected.
Under the Schedule tab, ensure the "Run Task:" option is set to at "Weekly" or more frequent.

Criteria:  If the "Enable (scheduled task runs at a specified time)" option is selected and the "Schedule Type:" is at least "Weekly", or more frequent, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on demand client scan task. 

Criteria:  If the value for bSchedEnabled is not 1, this is a finding.
If the value for eScheduletype is not either 0 or 1, this is a finding.  
If the value for bSchedEnabled is 1 and the value for eScheduletype is  0 or 1 this is not a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Click on the Schedule button.
Under the Task tab, select "Enabled".
Under the Schedule tab, find the "Run Task: " label and set to at least "Weekly". 


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6627'
  tag rid: 'SV-56426r1_rule'
  tag stig_id: 'DTAM070'
  tag gtitle: 'DTAM070-McAfee VirusScan schedule'
  tag fix_id: 'F-49131r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

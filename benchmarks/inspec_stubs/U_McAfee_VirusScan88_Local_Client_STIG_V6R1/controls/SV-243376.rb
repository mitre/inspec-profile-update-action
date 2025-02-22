control 'SV-243376' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan all subfolders.'
  desc 'Antivirus software is the mostly commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives and folders regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, locate the "Scan options:" label. Ensure the "Include subfolders" option is selected.

Criteria:  If "Include subfolders" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the bScanSubdirs has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, locate the "Scan options:" label. Select the "Include subfolders" option.


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46651r722465_chk'
  tag severity: 'medium'
  tag gid: 'V-243376'
  tag rid: 'SV-243376r722467_rule'
  tag stig_id: 'DTAM046'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46608r722466_fix'
  tag 'documentable'
  tag legacy: ['V-6614', 'SV-56419']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

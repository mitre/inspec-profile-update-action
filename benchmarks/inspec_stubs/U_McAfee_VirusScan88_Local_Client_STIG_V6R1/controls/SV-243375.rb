control 'SV-243375' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan all fixed, or local, disks and running processes.'
  desc 'Antivirus software is the mostly commonly used technical control for malware threat mitigation. Antivirus software on hosts should be configured to scan all hard drives regularly to identify any file system infections and to scan any removable media, if applicable, before media is inserted into the system. Not scheduling a regular scan of the hard drives of a system and/or not configuring the scan to scan all files and running processes, introduces a higher risk of threats going undetected.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, in the box under the "Specify where scanning takes place." label, ensure both "All fixed drives" or "All local drives" and "Running processes" options are included.

Criteria:  If "All fixed drives" or "All local drives" and "Running processes" are displayed in the configuration for the daily or weekly On Demand Scan, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with the weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, there exists a szScanItem with a REG_SZ value of "FixedDrives" or "LocalDrives" and a szScanItem with a REG_SZ value of "SpecialMemory", this is not a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task,  with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Locations tab, in the box under the "Specify where scanning takes place." label, click the "Add" button and add "All fixed drives" or "All local drives" and "Running processes" options from the drop-down selection.

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46650r722462_chk'
  tag severity: 'medium'
  tag gid: 'V-243375'
  tag rid: 'SV-243375r722464_rule'
  tag stig_id: 'DTAM045'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46607r722463_fix'
  tag 'documentable'
  tag legacy: ['V-6612', 'SV-56404']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

control 'SV-216964' do
  title 'McAfee VirusScan On-Demand scan must be configured to scan memory for rootkits.'
  desc 'A rootkit is a stealthy type of software, usually malicious, and is designed to mask the existence of processes or programs from normal methods of detection. Rootkits will often enable continued privileged access to a computer. Scanning and handling detection of rootkits will mitigate the likelihood of rootkits being installed and used maliciously on the system.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Actions column, select "Edit Assignment". In the Task to Schedule: area, verify the Product is "VirusScan Enterprise 8.8.0" and the Task Type is "On Demand Scan". In the Task name column, select "View Selected Task". Under the Scan Locations tab, locate the "Locations to scan:" label. Ensure the "Memory for rootkits" option is displayed.

Criteria: If "Memory for rootkits" is displayed in the configuration for the daily or weekly On Demand Scan, this is not a finding.

Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)

If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.

Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line is provided to describe the type of scan. In this case, TaskType=VSC700_Scan_Task is expected. Information for this check is determined by examining the contents of this file.

Criteria: If [ScanItems] szScanItemX=SpecialScanForRootkits is present, this is not a finding. For the values of szScanItemX, the character X represents some integer =>0. Example: szScanItem0=All fixed disks, szScanItem1=SpecialMemory.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Task Name column, select the weekly on demand task. Under the Scan Locations tab, locate the "Locations to scan:" label. In the drop-down menus, select "Memory for rootkits". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18194r309621_chk'
  tag severity: 'medium'
  tag gid: 'V-216964'
  tag rid: 'SV-216964r397867_rule'
  tag stig_id: 'DTAM154'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-18192r309622_fix'
  tag 'documentable'
  tag legacy: ['SV-55260', 'V-42532']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

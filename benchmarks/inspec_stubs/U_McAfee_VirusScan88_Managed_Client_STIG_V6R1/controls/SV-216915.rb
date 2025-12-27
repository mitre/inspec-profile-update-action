control 'SV-216915' do
  title 'McAfee VirusScan On-Demand scan must be configured so there are no exclusions from the scan unless exclusions have been documented with, and approved by, the ISSO/ISSM/DAA.'
  desc 'When scanning for malware, excluding specific files will increase the risk of a malware-infected file going undetected. By configuring antivirus software without any exclusions, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Actions column, select "Edit Assignment". In the Task to Schedule: area, verify the Product is "VirusScan Enterprise 8.8.0" and the Task Type is "On Demand Scan". In the Task name column, select "View Selected Task". Under the Exclusions tab, locate the "What not to scan:" label. Ensure that no items are listed in this area.

Criteria: If no items are listed in the "What not to scan:" area, this is not a finding.
If excluded items exist, and they are documented with and approved by the ISSO/ISSM/DAA, this is not a finding.
If excluded items exist, and they are not documented with and approved by the ISSO/ISSM/DAA, this is a finding.

Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)

If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.

Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line is provided to describe the type of scan. In this case, TaskType=VSC700_Scan_Task is expected. Information for this check is determined by examining the contents of this file.

Criteria: If [Exclusions] dwExclusionCount=0, this is not a finding.
Criteria: If dwExclusionCount is not set to 0, ensure the justification for exclusions found have been documented with the ISSO/ISSM/DAA. If exclusions are documented with the ISSO/ISSM/DAA, this is not a finding. If exclusions have not been documented, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Task Name column, select the weekly on demand task. Under the Exclusions tab, locate the "What not to scan:" label. Ensure that no items are listed in this area.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18145r309474_chk'
  tag severity: 'medium'
  tag gid: 'V-216915'
  tag rid: 'SV-216915r397867_rule'
  tag stig_id: 'DTAM050'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-18143r309475_fix'
  tag 'documentable'
  tag legacy: ['SV-55195', 'V-6604']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

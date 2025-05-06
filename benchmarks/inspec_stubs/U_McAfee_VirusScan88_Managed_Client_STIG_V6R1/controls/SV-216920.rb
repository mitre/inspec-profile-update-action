control 'SV-216920' do
  title 'McAfee VirusScan On-Demand scan actions, When a threat is found must be configured to clean files automatically as first action.'
  desc 'Malware may have infected a file that is necessary to the user. By configuring the antivirus software to first attempt cleaning the infected file, availability to the file is not sacrificed. If a cleaning attempt is not successful, however, deleting the file is the only safe option so as to ensure the malware is not introduced onto the system or network.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Actions column, select "Edit Assignment". In the Task to Schedule: area, verify the Product is "VirusScan Enterprise 8.8.0" and the Task Type is "On Demand Scan". In the Task name column, select "View Selected Task". Under the Actions tab, locate the "When a threat is found:" label. Ensure that from the "Perform this action first:" pull down menu, "Clean files" is selected.

Criteria: If "Clean files" is selected for "Perform this action first", this is not a finding.
Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)

If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.

Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line is provided to describe the type of scan. In this case, TaskType=VSC700_Scan_Task is expected. Information for this check is determined by examining the contents of this file.

Criteria: If [Action] uAction is not set to 5, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Task Name column, select the weekly on demand task. Under the Actions tab, locate the "When a threat is found:" label. From the "Perform this action first:" pull down menu, select "Clean files". Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18150r309489_chk'
  tag severity: 'medium'
  tag gid: 'V-216920'
  tag rid: 'SV-216920r397873_rule'
  tag stig_id: 'DTAM056'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-18148r309490_fix'
  tag 'documentable'
  tag legacy: ['SV-55203', 'V-6616']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

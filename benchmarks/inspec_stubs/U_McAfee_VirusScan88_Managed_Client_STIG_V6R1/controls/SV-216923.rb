control 'SV-216923' do
  title 'McAfee VirusScan On-Demand scan must be configured to record scanning activity in a log file.'
  desc 'Log management is essential to ensuring that computer security records are stored in sufficient detail for an appropriate period of time. Routine log analysis is beneficial for identifying security incidents, policy violations, fraudulent activity, and operational problems. Logs are also useful when performing auditing and forensic analysis, supporting internal investigations, establishing baselines, and identifying operational trends and long-term problems.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Actions column, select "Edit Assignment". In the Task to Schedule: area, verify the Product is "VirusScan Enterprise 8.8.0" and the Task Type is "On Demand Scan". In the Task name column, select "View Selected Task". Under the Reports tab, locate the "Log to file:" label. Ensure the "Enable activity logging and accept the default location for the log file or specify a new location" option is selected.

Criteria: If "Enable activity logging and accept the default location for the log file or specify a new location" is selected, this is not a finding.
Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)

If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.
Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line is provided to describe the type of scan. In this case, TaskType=VSC700_Scan_Task is expected. Information for this check is determined by examining the contents of this file.

Criteria: If [Reports] bLogToFile=1, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Task Name column, select the weekly on demand task. Under the Reports tab, locate the "Log to file:" label. Select the "Enable activity logging and accept the default location for the log file or specify a new location" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18153r309498_chk'
  tag severity: 'medium'
  tag gid: 'V-216923'
  tag rid: 'SV-216923r397867_rule'
  tag stig_id: 'DTAM059'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-18151r309499_fix'
  tag 'documentable'
  tag legacy: ['SV-55209', 'V-6618']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

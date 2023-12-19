control 'SV-216924' do
  title 'McAfee VirusScan On-Demand scan log file size must be restricted and be configured to at least 10MB.'
  desc 'While logging is imperative to forensic analysis, logs could grow to the point of impacting disk space on the system. In order to avoid the risk of logs growing to the size of impacting the operating system, the log size will be restricted, but must also be large enough to retain forensic value.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Actions column, select "Edit Assignment". Locate the "Task to Schedule:" label. Verify the Product is "VirusScan Enterprise 8.8.0" and the Task Type is "On Demand Scan". In the Task name column, select "View Selected Task". 

Under the Reports tab, locate the "Log file size:" label. 
Criteria: If the "Limit the size of log file" option is selected and the "Maximum log file size:" is at least 10MB, this is not a finding. 

Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)

If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.

Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line is provided to describe the type of scan. In this case, TaskType=VSC700_Scan_Task is expected. Information for this check is determined by examining the contents of this file.
Criteria: If the value of bLimitSize value is not 1, this is a finding.
If the uKilobytes is less than 10240 (Decimal), this is a finding.
If the bLimitSize value is 1 and the uKilobytes value is 10240 (Decimal) or more, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. From the list of available tasks in the Task Name column, with the assistance of the ePO SA, identify the weekly on demand client scan task. In the same row as the client scan task under review, under the Task Type column, ensure it is an "On Demand scan" and in the Status column, ensure that the status is "Enabled". In the Task Name column, select the weekly on demand task. Under the Reports tab, locate the "Log file size:" label. Select the "Limit the size of log file" option. For the "Maximum log file size:", select a value of 10MB or more. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18154r309501_chk'
  tag severity: 'medium'
  tag gid: 'V-216924'
  tag rid: 'SV-216924r397867_rule'
  tag stig_id: 'DTAM060'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-18152r309502_fix'
  tag 'documentable'
  tag legacy: ['SV-55211', 'V-6620']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

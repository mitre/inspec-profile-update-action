control 'SV-55151' do
  title 'McAfee VirusScan must be configured to receive DAT and Engine updates.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The antivirus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'Note: Automatic updates to antivirus signature definitions are to be performed once every 24 hours for hosts connected to the network.

From the ePO server console System Tree, select the "Systems" tab, select the asset to be checked, select Actions, select Agent, and select Modify Tasks on a Single System. Verify there is a Product Update task type enabled. Select the Task Name, locate the "Package Types:" label. Ensure Engine and DAT are selected.
Criteria: 

If a Product update is Enabled with Engine and DAT selected, and scheduled for at least a daily update, this is not a finding.

Locally, on the client machine, use the Windows Explorer to navigate to the following folder: (This folder may be hidden.)
%SystemDrive%\\ProgramData\\McAfee\\Common Framework\\Task (64-Bit)
Multiple .ini files will be stored in this folder, one for each task defined on the ePO server for this client. If folder(s) do not exist, an alternative method of validating is via the following registry key:
[HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\McAfee\\DesktopProtection\\Tasks] and are referenced by a GUID for each task.

The name for each task is identified in the first section of the file under the [Task] section on the TaskName= "" line. Additionally, a TaskType= line in the [General] section of the file is provided to describe the task type. In this case, TaskType=update is expected. Information for this check is determined by examining the contents of this file. 

Criteria: If [Settings] Enabled=1 and [Schedule] Type=0, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset for the task assignment, select Actions, select Agent, and Select Modify Tasks on a Single System.  Select Actions, and select New Client Task Assignment. In the Task to Schedule: area, select McAfee Agent for the product. Select Product Update for the Task Type. Select Create New Task. Provide a descriptive name for the task. Locate the "Package Types:" label. Select the "Engine" and "DAT" options.  Select Save. On the Schedule page, locate the "Schedule Status:" label, and select the "Enabled" option.  Locate the "Schedule type:" label, and from the pull down menu, select at least "Daily". Select Next. On the Summary page, verify the settings and select Save. Update the client machine.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48781r7_chk'
  tag severity: 'medium'
  tag gid: 'V-6585'
  tag rid: 'SV-55151r4_rule'
  tag stig_id: 'DTAM016'
  tag gtitle: 'DTAM016-McAfee VirusScan autoupdate parameters'
  tag fix_id: 'F-48009r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end

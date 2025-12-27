control 'SV-61873' do
  title 'The antivirus signature file age must not exceed 7 days.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. By configuring a system to attempt an antivirus update on a daily basis, the system is ensured of maintaining an antivirus signature age of 7 days or less. If the update attempt were to be configured for only once a week, and that attempt failed, the system would be immediately out of date.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

On the System Information page, select the "Products" tab. Under the Product section, select "VirusScan Enterprise for Linux".
Scroll down locate the DAT Date and DAT Version.

Verify the "DAT Date:" is within the last 7 days.

If the "DAT Date:" is not within the last 7 days, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

On the Client Tasks page, click on Actions | New Client Task Assignment. 

On the Client Task Assignment Builder page, under the "Product" section, select "McAfee Agent". 
Under the "Task Type" section, select "Product Update". 
Under the "Task Name" section, click on "Create New Task".

Type a unique name for the "Task Name".
For "Package selection:", select the "All packages" radio button. Click Save.

Or, select the "Selected packages" radio button.
For the "Package types:" section, select the "DAT" check box and the "Linux Engine" check box under the "Signatures and engines:" section.
Click Save.

On the Client Task Assignment Builder page, under the "Task Name" section, select the task just created.
Click on "Next" to schedule the task.
For "Schedule status:", select the radio button for "Enabled".
For "Schedule type:", choose "Daily".
Schedule the "Effective period:", "Start time:" and other options according to best practices.
Click Next to view Summary.
Click Save.'
  impact 0.7
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49428r6_chk'
  tag severity: 'high'
  tag gid: 'V-48995'
  tag rid: 'SV-61873r1_rule'
  tag stig_id: 'DTAVSEL-001'
  tag gtitle: 'DTAVSEL-001 McAfee MOVE Agentless antivirus signature age'
  tag fix_id: 'F-49520r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

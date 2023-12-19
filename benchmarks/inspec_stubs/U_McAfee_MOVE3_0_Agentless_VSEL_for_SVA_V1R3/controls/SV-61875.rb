control 'SV-61875' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 must be configured to receive automatic signature updates.'
  desc 'Antivirus signature files are updated almost daily by antivirus software vendors. These files are made available to antivirus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. The antivirus software product must be configured to receive those updates automatically in order to afford the expected protection.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Tasks on a Single System.  

From the list of available tasks in the "Task Name" column, with the assistance of the ePO SA, identify the VirusScan DAT update task.
Verify the "Task Type" is listed as "Product Update".
Verify the "Status" is listed as "Enabled".

Under the "Task Name" column, click on the link for the designated task to review the task properties.
Next to the "Package selection:", verify the "All packages" radio button is selected. 
If the "Selected packages" radio button is selected, verify the check box for "DAT" and the check box for "Linux Engine" have been selected for "Signatures and engines:" under the "Package types:" section.

If there is not a task designated as the regularly scheduled DAT Update task, this is a finding.
If there exists a task designated as the regularly scheduled DAT Update task, but neither the "All packages" nor the "DAT" selection under the "Package types: Signatures and engines:" section is selected, this is a finding.'
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

On the Client Task Assignment Builder, under the "Task Name" section, select the task just created.
Click on "Next" to schedule the task.
For "Schedule status:", select the radio button for "Enabled".
For "Schedule type:", choose "Daily".
Schedule the "Effective period:", "Start time:" and other options according to best practices.
Click Next to view Summary.
Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49430r5_chk'
  tag severity: 'medium'
  tag gid: 'V-48997'
  tag rid: 'SV-61875r1_rule'
  tag stig_id: 'DTAVSEL-002'
  tag gtitle: 'DTAVSEL-002 - McAfee VSEL for SVA automatic signature updates'
  tag fix_id: 'F-49541r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

control 'SV-77283' do
  title 'The anti-virus signature file age must not exceed 7 days.'
  desc 'Anti-virus signature files are updated almost daily by anti-virus software vendors. These files are made available to anti-virus clients as they are published. Keeping virus signature files as current as possible is vital to the security of any system. By configuring a system to attempt an anti-virus update on a daily basis, the system is ensured of maintaining an anti-virus signature age of 7 days or less. If the update attempt were to be configured for only once a week, and that attempt failed, the system would be immediately out of date.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 
On the System Information page, select the "Products" tab. Under the "Product" section, select "VirusScan Enterprise for Linux".
Scroll down. Locate the DAT Date and DAT Version.
Verify the "DAT Date:" is within the last 7 days.

If the "DAT Date:" is not within the last 7 days, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page. 
Click on Actions >> Agent >> Modify Tasks on a Single System.
On the Client Tasks page, click on Actions >> New Client Task Assignment.
On the Client Task Assignment Builder page, under the "Product" section, select "McAfee Agent".
Under the "Task Type" section, select "Product Update".
Under the "Task Name" section, click on "Create New Task".
Type a unique name for the "Task Name".
For "Package selection:", select the "All packages" radio button.
Click "Save".

Or

Select the "Selected packages" radio button. 
For the "Package types:" section, select the "DAT" check box and the "Linux Engine" check box under the "Signatures and engines:" section.
Click "Save".
On the Client Task Assignment Builder page, under the "Task Name" section, select the task just created.
Click on "Next" to schedule the task.
For "Schedule status:", select the radio button for "Enabled".
For "Schedule type:", choose "Daily".
Schedule the "Effective period:", "Start time:" and other options according to best practices.
Click "Next" to view Summary.
Click "Save".'
  impact 0.7
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63601r1_chk'
  tag severity: 'high'
  tag gid: 'V-62793'
  tag rid: 'SV-77283r1_rule'
  tag stig_id: 'DTAVSEL-001'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-68713r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

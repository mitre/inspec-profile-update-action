control 'SV-93273' do
  title 'The McAfee MOVE AV SVM must be managed by the HBSS ePO server.'
  desc 'Organizations should use centrally managed anti-virus software that is controlled and monitored regularly by anti-virus administrators, who are also typically responsible for acquiring, testing, approving, and delivering anti-virus signature and software updates throughout the organization. Users should not be able to disable or delete anti-virus software from their hosts, nor should they be able to alter critical settings. Anti-virus administrators should perform continuous monitoring to confirm that hosts are using current anti-virus software and that the software is configured properly. Implementing all of these recommendations should strongly support an organization in having a strong and consistent anti-virus deployment across the organization.'
  desc 'check', 'Access the server designated as the McAfee MOVE SVM. In the taskbar, right-click the red McAfee Agent shield and select "McAfee Agent Status Monitor". 

Click the "Collect and Send Props" button. This will perform the ASCI, send the PROPS VERSION package to the ePO, and close the session. 

Click the "Enforce Policies" button. In the McAfee Agent Monitor, review the Management status lines and ensure one shows a status of "Enforcing Policies for DC_AM_4000" and "Enforcing Policies for DC_GS_4000". This status lines will confirm the system is enforcing policies for the McAfee MOVE AV SVM. 

If the system does not show "Agent started performing ASCI", followed by a sequence of status lines showing the "Agent is sending PROPS VERSION package to ePO server" and "Agent communication session closed", or does not show a Management status line of "Enforcing Policies for DC_AM_4000" and "Enforcing Policies for DC_GS_4000", this is a finding.'
  desc 'fix', 'Access the ePO server. From the system tree, select the "Systems tab" and find and click on the asset representing the McAfee MOVE SVM to open its properties. 

If the asset representing the McAfee MOVE SVM is not in the ePO server system tree, configure a task to deploy the McAfee Agent to the system designated as the McAfee MOVE SVM.

Once the system is communicating with the ePO server and is in the ePO server system tree, find and click on the asset representing the McAfee MOVE SVM to open its properties. 

Click on Actions >> Agent >> Modify Tasks on a Single System. 

Click on "Actions" and select "New Client Task Assignment". 

Under "Product", select "McAfee Agent". 

Under "Task Type", select "Product Deployment".

Under "Task Name", select "Create New Task." 

Next to "Task Name", enter "Deploy MOVE to the SVM". 

Next to "Target Platforms", ensure only "Windows" is selected. 

In the drop-down box for "Products and components", select "MOVE AV [Multi-Platform] SVM 4.5x" and ensure the drop-down box for "Action" is set to "Install". 

Click "Save". 

Click "Next".
 
For the "Schedule status:", select "Enabled". 

Configure the schedule variable in accordance with local Change Control policy and click "Next". 

On "Summary" tab, click "Save" and then "Close". 

Back at the "System Information" screen, click on the "Wake Up Agents" button. 

In the "Wake Up McAfee Agent" screen, for the "Force policy update:" settings, place a check in the "Force complete policy and task update" check box. 

Click "OK".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78567'
  tag rid: 'SV-93273r1_rule'
  tag stig_id: 'MV45-SVM-000003'
  tag gtitle: 'MV45-SVM-000003'
  tag fix_id: 'F-85303r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

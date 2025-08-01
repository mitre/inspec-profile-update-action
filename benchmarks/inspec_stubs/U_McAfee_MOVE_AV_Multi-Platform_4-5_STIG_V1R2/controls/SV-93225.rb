control 'SV-93225' do
  title 'The McAfee MOVE AV policies must be configured with and managed by the HBSS ePO server.'
  desc 'Organizations should use centrally managed anti-virus software that is controlled and monitored regularly by anti-virus administrators, who are also typically responsible for acquiring, testing, approving, and delivering anti-virus signature and software updates throughout the organization. Users should not be able to disable or delete anti-virus software from their hosts, nor should they be able to alter critical settings. Anti-virus administrators should perform continuous monitoring to confirm that hosts are using current anti-virus software and that the software is configured properly. Implementing all of these recommendations should strongly support an organization in having a strong and consistent anti-virus deployment across the organization.'
  desc 'check', 'On the system being reviewed, first confirm the system has a McAfee Agent deployed and running. 

Click "Start" and type "services.msc" in the "Search programs and files" search bar.

Review the services running on the system. 

Ensure the "McAfee Agent Common Services" and "McAfee Agent Service" are listed as services and have a status of "Started". 

If the system does not have the McAfee Agent deployed to it, this is a finding. 

If the McAfee Agent is running on the system, confirm the system has the "MOVE AV [Multi-Platform] Client 4.5.0" policies being enforced by ePO.

Navigate to the directory to which the McAfee Agent is installed (default is C:\\Program Files\\McAfee\\Agent). 

Open the McAfee Agent status monitor by executing the following command: 

cmdagent /s 

In the McAfee Agent Monitor, click the "Collect and Send Props" button. Review the "Agent Subsystem" status lines and ensure there is a status for "Agent started performing ASCI", followed by a sequence of status lines showing the "Agent is sending PROPS VERSION package to ePO server" and "Agent communication session closed". These status lines will confirm the system is making a successful connection to the ePO server.

Click the "Enforce Policies" button. In the McAfee Agent Monitor, review the "Management" status lines and ensure one shows a status of enforcing policies for the McAfee Move Client 4.5.

If McAfee Agent Status Monitor shows successful "Agent Subsystem" status lines of "Agent started performing ASCI", followed by a sequence of status lines showing the "Agent is sending PROPS VERSION package to ePO server" and "Agent communication session closed" but the "Management" status line does not show it is enforcing policies for the McAfee MOVE Client 4.5, this is a finding.'
  desc 'fix', 'Access the ePO server. From the system tree, select the "Systems" tab and find and click on the asset to which the "MOVE AV [Multi-Platform] Client 4.5.0" needs to be deployed to open its properties.

If the asset is not in the ePO server system tree, configure a task to deploy the McAfee Agent to the asset to which the "MOVE AV [Multi-Platform] Client 4.5.0" will be deployed and proceed to next step.

If the asset is in the ePO server system tree, click on the asset to which the "MOVE AV [Multi-Platform] Client 4.5.0" needs to be deployed to open its properties.

Select Menu >> Policy >> Client Task Catalog.

Select "Product Deployment" in the "Client Task Types" menu and then select >> Actions >> New Task.

Select "Product Deployment" from the list and then click "OK" to open the "Client Task Builder" wizard.

Type a name for the task being created and add any descriptive information in the "Description" field.

Ensure that "Windows" is the only target platform selected.

For "Products and components":
For "client", select "MOVE AV [Multi-Platform] Client 4.5.0" from the drop-down list.
Set the "action" to "Install".
Set the "language" to "Language Neutral".
Set the "branch" to "Current".

Leave the "Command line" setting blank.

Review the task settings and click "Save".

Assign the newly created task to the asset being reviewed.

Send a wake-up call to the asset being reviewed.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78519'
  tag rid: 'SV-93225r1_rule'
  tag stig_id: 'MV45-GEN-000002'
  tag gtitle: 'MV45-GEN-000002'
  tag fix_id: 'F-85253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

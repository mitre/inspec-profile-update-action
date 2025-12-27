control 'SV-213341' do
  title 'The McAfee Application Control Options Inventory interval option must be configured to pull inventory from endpoints on a regular basis not to exceed seven days.'
  desc 'When McAfee Application Control is deployed on a system, it creates a whitelist of all executable binaries and scripts present on the system. The whitelist contains all authorized files, and only files that are present in the whitelist are allowed to execute. An executable binary, script, or process that is not in the whitelist is said to be unauthorized and is prevented from running. McAfee Application Control uses a centralized repository of trusted applications and dynamic whitelisting to reduce manual maintenance effort.

Running frequent Pull Inventory tasks ensures inventory information does not become stale. There must be the minimum interval between consecutive inventory pull runs (when the inventory information is fetched from the endpoints). By default, this value is 7 days and is the recommended setting. Pulling at an interval of greater than 7 days will allow for the inventory of endpoints to become stale.'
  desc 'check', 'Note: For VDI workstations that are reset copies of a VDI master image, this requirement is Not Applicable. For VDI master images, once an inventory is pulled after updates, further inventory is not required.
Note: This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

Consult with the ISSO to determine the endpoints used for the sampling of inventory pulls.

From the McAfee ePO console, select Menu >> Systems >> System Tree.

If sampling is a group, select the group in the System Tree and switch to the “Assigned Client Tasks” tab.

Otherwise, select each endpoint on the “Systems” page and then click Actions >> Agent >> Modify Tasks on a Single System.

Confirm a client task exists with an “SC: Pull Inventory” task type. Review the task properties to validate the task is configured to run at least as frequently as every 7 days and tasks randomize the inventory pulls.

If a sampling of endpoints does not have a “Pull Inventory” task type applied and/or the “Pull Inventory” task is not configured to run at least as frequently as every 7 days at randomized intervals, this is a finding.'
  desc 'fix', 'From the McAfee ePO console, select Menu >> Systems >> System Tree.

To apply a client task to a group, select a group in the System Tree and switch to the "Assigned Client Tasks" tab.

To apply a client task to an endpoint, select the endpoint on the "Systems" page and then click Actions >> Agent >> Modify Tasks on a Single System.

Click Actions >> New Client Task Assignment to open the "Client Task Assignment Builder" page.

Select "Solidcore 8.x" for the product and "SC: Pull Inventory" for the task type and then click "Create New Task" to open the "Client Task Catalog" page.
Specify the task name and add any descriptive information.

Click "Save".
Click "Next" to open the "Schedule" page. Schedule the task to run at least as frequently as every 7 days and then click "Next".

Review and verify the task details and then click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14569r557321_chk'
  tag severity: 'medium'
  tag gid: 'V-213341'
  tag rid: 'SV-213341r557322_rule'
  tag stig_id: 'MCAC-TE-000115'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14567r505059_fix'
  tag 'documentable'
  tag legacy: ['V-74243', 'SV-88917']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

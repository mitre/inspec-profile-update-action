control 'SV-88883' do
  title 'The Solidcore client must be enabled.'
  desc 'The Application Control whitelisting must be enabled on all workstation endpoints. To enable Application Control, the Solidcore client needs to be in enabled mode.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated and view its properties.

Click on the "Products" tab.

Under "Product", verify the Solidcore 7 client is listed as a product. If exists, click on the row to review additional information. Verify status shows "Enabled".

If the Solidcore 7 client is listed as an installed product but the status is not "Enabled", this is a finding.'
  desc 'fix', 'Although there is more than one way to deploy and enable the Solidcore client, the following is the method described in the McAfee Application Control Installation Guide.

From the ePO server console System Tree, select "My Organization" in the System Tree.

To deploy the Solidcore 7 client:

Select "This Group and All Subgroups".
Select the asset and view its properties.
Click on the "Actions" button at the bottom of the screen.
Select "Agent".
Select "Modify Tasks on a Single System".
Click "Actions".
Select "New Client Task Assignment" to open the "Client Task Assignment Builder" page.
Specify the task name and add descriptive information.
Select the target platform, subplatform, and version.
Select the "Solidcore 7.0.0" product from the "Products and components" list.
Select the "Install" action.
Select the language of the package.
Specify the branch where to add the package.
Click "Save", then click "Next to open the "Schedule" page.
Specify scheduling details, then click "Next".
Review details, then click "Save".

To enable the Solidcore 7 client and scan for inventory:

Select "This Group and All Subgroups".
Select the asset and view its properties.
Click on the "Actions" button at the bottom of the screen.
Select "Agent".
Select "Modify Tasks on a Single System".
Click "Actions".
Select "New Client Task Assignment" to open the "Client Task Assignment Builder" page.
Select the "Solidcore 7.0.0" product and "SC: Enable" task type, then click "Create New Task".

On the "Client Task Catalog" page, specify the task name and add descriptive information.
Select the platform, subplatform, and version.
Select "Application Control".
Specify the scan priority.
Specify "Full Feature Activation".
Select "Start Observe Mode".
Select "Pull Inventory".
Click "Save", then click "Next" to open the Schedule page.
Specify scheduling details, then click "Next".
Review details, then click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74245r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74209'
  tag rid: 'SV-88883r1_rule'
  tag stig_id: 'MCAC-TE-000100'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80751r5_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

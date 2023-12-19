control 'SV-213327' do
  title 'The Solidcore client Command Line Interface (CLI) must be in lockdown mode.'
  desc "By default, when an endpoint's Solidcore installation is managed by the ePO server, the CLI will automatically be in lockdown mode. This will ensure the endpoint receives all of its Solidcore configuration settings from the ePO server. The CLI can, however, be activated for troubleshooting efforts during which time the ePO settings will not be enforced. Leaving the CLI in an allowed status will prevent the endpoint from receiving changes from the ePO server for the Solidcore client."
  desc 'check', 'Determine CLI status.

Access the system being reviewed. From an operating system command line, execute the following command:

sadmin status <enter>

If the status for CLI is "Allowed" or "Recovered", this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Click "Actions".
Select "New Client Task Assignment" to open the Client Task Assignment Builder page.

Select the "Solidcore 8.x product", "SC: Change Local CLI Access" task type, then click "Create New Task" to open the Client Task Catalog page.

Change "CLI status" to "Restrict".

Click "Save".'
  impact 0.7
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14555r309078_chk'
  tag severity: 'high'
  tag gid: 'V-213327'
  tag rid: 'SV-213327r506897_rule'
  tag stig_id: 'MCAC-TE-000101'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-14553r309079_fix'
  tag 'documentable'
  tag legacy: ['V-74211', 'SV-88885']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

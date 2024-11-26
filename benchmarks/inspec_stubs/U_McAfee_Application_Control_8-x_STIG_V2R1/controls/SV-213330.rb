control 'SV-213330' do
  title 'The McAfee Application Control Options Reputation setting must be configured to use the McAfee Global Threat Intelligence (McAfee GTI) option.'
  desc 'If a Threat Intelligence Exchange (TIE) server is being used in the organization, reputation for files and certificates is fetched from the TIE server. The reputation values control execution at endpoints and are displayed on the Application Control pages on the McAfee ePO console.

If the GTI is being used, reputation for files and certificates is fetched from the McAfee GTI.

For both methods, the administrator can review the reputation values and make informed decisions for inventory items in the enterprise.'
  desc 'check', 'NOTE: This requirement is Not Applicable on a classified SIPRNet or otherwise closed network.

This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset(s) that need the organization-specific policy.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Verify the "Use McAfee Global Threat Intelligence (McAfee GTI)" option is selected.

Note: The "McAfee GTI" option must be selected, as a failover, even if an internal McAfee TIE server is configured.

If the "McAfee GTI" option is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Place a check in the "Use McAfee Global Threat Intelligence (McAfee GTI)" option.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14558r505025_chk'
  tag severity: 'medium'
  tag gid: 'V-213330'
  tag rid: 'SV-213330r506897_rule'
  tag stig_id: 'MCAC-TE-000104'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14556r505026_fix'
  tag 'documentable'
  tag legacy: ['V-74217', 'SV-88891']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

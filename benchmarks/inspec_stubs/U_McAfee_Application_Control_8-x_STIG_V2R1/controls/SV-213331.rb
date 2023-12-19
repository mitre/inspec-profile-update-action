control 'SV-213331' do
  title 'The McAfee Application Control Options Reputation-Based Execution settings, if enabled, must be configured to allow Most Likely Trusted or Known Trusted only.'
  desc 'When a file is executed on an endpoint, the Application Control performs multiple checks to determine whether to allow or ban the execution. Only files with a reputation of "Most Likely Trusted", "Known Trusted" or "Might be Trusted" are considered to be allowed. By configuring the setting to only "Most Likely Trusted" or "Known Trusted", the files with a reputation of "Might be Trusted" are blocked. While this may impact operationally in the beginning, after the inventories are vetted by the administrators, files with a "Might be Trusted" value may be recategorized in that organization.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

If Reputation-Based Execution settings is not enabled, this check is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset(s) that need the organization-specific policy.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Verify the "Reputation-Based Execution Settings" is configured to allow binaries with "Most Likely Trusted" and above.

If the allow binaries "Most Likely Trusted" and above is not selected for "Reputation-Based Execution Settings", this is a finding.'
  desc 'fix', 'If Reputation-Based Execution settings is not enabled, this check is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Place a check in the "Reputation-Based Execution Settings: Allow binaries with" check box and select "Most Likely Trusted" from the drop-down selection box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14559r505028_chk'
  tag severity: 'medium'
  tag gid: 'V-213331'
  tag rid: 'SV-213331r506897_rule'
  tag stig_id: 'MCAC-TE-000105'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14557r505029_fix'
  tag 'documentable'
  tag legacy: ['V-74223', 'SV-88897']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

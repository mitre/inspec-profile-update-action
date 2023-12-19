control 'SV-213333' do
  title 'The McAfee Application Control Options Advanced Threat Defense (ATD) settings, if being used, must be configured to send all binaries with a reputation of Might be Trusted and below for analysis.'
  desc 'When the file reputation of "Might be Trusted" is configured for being forwarded to ATD, all files with the reputation of "Might be Trusted", "Unknown", "Might be Malicious", "Most Likely Malicious" and "Known Malicious" are forwarded to the ATD.

The files with "Might be Trusted" reputation may be redesignated as "Trusted" after analysis.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

If an ATD server is not being used in the environment, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control. From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

If the option for sending binaries for analysis under the "Advanced Threat Defense (ATD) settings" is selected, verify the level of binaries to be sent for analysis is "Might be Trusted" and below.

If the level of binaries to be sent for analysis is not "Might be Trusted", this is a finding.'
  desc 'fix', 'If an ATD server is not being used in the environment, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

In the drop-down selection box of the "Advanced Threat Defense (ATD) settings: Send binaries" option, select "Might be Trusted".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14561r505034_chk'
  tag severity: 'medium'
  tag gid: 'V-213333'
  tag rid: 'SV-213333r506897_rule'
  tag stig_id: 'MCAC-TE-000107'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14559r505035_fix'
  tag 'documentable'
  tag legacy: ['SV-88901', 'V-74227']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end

control 'SV-213337' do
  title 'The McAfee Application Control Options policy End User Notification, if configured by organization, must have all default variables replaced with the organization-specific data.'
  desc 'The "User Message" option will show a dialog box when an event is detected and display the organization-specified text in the message.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

If "End User Notification" is not used by the organization, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "End User Notification" tab, determine if the "User Message:" option "Show the messages dialog box when an event is detected and display the specified text in the message." is selected.

If "Show the messages dialog box when an event is detected and display the specified text in the message." is not selected, this is Not Applicable.

If "Show the messages dialog box when an event is detected and display the specified text in the message." is selected, consult with the ISSO/ISSM to review the organizational-specific written policy for the McAfee Application Control software.

Verify the usage of "End User Notification" is documented in the written policy and verify criteria for configuration.

If "End User Notification:" variables are not configured to written documentation, this is a finding.

If "End User Notification" is not documented in written policy, this is a finding.'
  desc 'fix', %q(If "End User Notification" is not used by the organization, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "End User Notification" tab, select or de-select the "Show the messages dialog box when an event is detected and display the specified text in the message." based upon organization's written policy.

If "Show the messages dialog box when an event is detected and display the specified text in the message." is de-selected based upon written policy, populate "Helpdesk Information" with information from the written policy.

Click "Save".

If "Show the messages dialog box when an event is detected and display the specified text in the message." is selected based upon written policy, populate "Helpdesk Information" with information from the written policy.

Click "Save".)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14565r505046_chk'
  tag severity: 'medium'
  tag gid: 'V-213337'
  tag rid: 'SV-213337r506897_rule'
  tag stig_id: 'MCAC-TE-000111'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14563r505047_fix'
  tag 'documentable'
  tag legacy: ['SV-88909', 'V-74235']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

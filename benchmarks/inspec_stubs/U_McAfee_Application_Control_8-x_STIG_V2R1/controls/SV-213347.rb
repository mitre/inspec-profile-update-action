control 'SV-213347' do
  title 'The Solidcore Client Exception Rules must be documented in the organizations written policy.'
  desc "When exceptions are created for applications, it results in potential attack vectors. As such, exceptions should only be created with a full approval by the local ISSO/ISSM. The organization's entire written policy requires approval by the ISSO/ISSM/AO and is required to be under CAB/CCB oversight."
  desc 'check', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

For Windows platforms, from the "Policy" column, select the policy associated with the Category "Exception Rules (Windows)" that is specific to the organization.

For Unix Platforms, from the "Policy" column, select the policy associated with the Category "Exception Rules (Unix)" that is specific to the organization.


If the "Exception Rules" policy applied to the system has exceptions documented, verify the exceptions are documented in the organization's written policy.

If the Exceptions are not documented, this is a finding.)
  desc 'fix', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

For Windows Platforms, from the "Policy" column, select the policy associated with the Category "Exception Rules (Windows)" that is specific to the organization.

For MAC/Unix Platforms, from the "Policy" column, select the policy associated with the Category "Exception Rules (Unix)" that is specific to the organization.

Remove any exceptions which are not documented in the organization's written policy.

If any exceptions are required, follow the formal change and acceptance process to document the required exceptions in the organization's written policy.)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14575r505076_chk'
  tag severity: 'medium'
  tag gid: 'V-213347'
  tag rid: 'SV-213347r506897_rule'
  tag stig_id: 'MCAC-TE-000123'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14573r505077_fix'
  tag 'documentable'
  tag legacy: ['V-74257', 'SV-88931']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

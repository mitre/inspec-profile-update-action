control 'SV-237436' do
  title 'The Microsoft SCOM server must use an active directory group that contains authorized members of the SCOM Administrators Role Group.'
  desc 'During the initial installation, SCOM grants the Builtin\\Administrators group administrator rights to the application. This configuration will allow any local administrator to the SCOM server to have full administrative rights into SCOM.'
  desc 'check', 'Open the Operations Console and select the Administrative workspace.

In the left pane, expand Security and select User Roles. In the center pane, double-click on Operations Manager Administrators.

If Builtin\\Administrators is listed, this is a finding.'
  desc 'fix', "From Active Directory Users and Computers, create a group following the organizational naming standards for SCOM Administrators. Add the SCOM service accounts to this group along with any user's administrative account that is required to administer SCOM. Make note of the group name.

Log on to the SCOM console with an administrative account. Select the Administration workspace. Expand Security and click User Roles. From the center pane, double-click on Operations Manager Administrators.

Click the Add button and type the name of the group created above and click Check Names. The name should validate. Click OK.

The new group should now be added to the Operations Manager Administrators role. Click on Builtin\\Administrators and click Remove. Click OK."
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40655r643952_chk'
  tag severity: 'medium'
  tag gid: 'V-237436'
  tag rid: 'SV-237436r643954_rule'
  tag stig_id: 'SCOM-IA-000002'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-40618r643953_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end

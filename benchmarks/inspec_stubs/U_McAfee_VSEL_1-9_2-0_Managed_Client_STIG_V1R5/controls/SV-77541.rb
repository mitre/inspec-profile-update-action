control 'SV-77541' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x Web UI must be disabled.'
  desc 'If the Web UI was left enabled, the system to which the VSEL has been installed would be vulnerable for Web attacks. Disabling the Web UI will prevent the system from listening on HTTP.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".
From the "Policy" column, click on the policy for the "General Policies".
In the "Advanced" tab, verify the check box for "Disable client Web UI:" is selected.

If the check box for "Disable client Web UI:" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list.

From the list of systems, locate the asset representing the Linux system being reviewed. Click on the system to open the System Information page.

Click on Actions >> Agent >> Modify Policies on a Single System.

From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.x/2.0.x".
From the "Policy" column, click on the policy for the "General Policies".
In the "Advanced" tab, select the check box for "Disable client Web UI:".

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63051'
  tag rid: 'SV-77541r1_rule'
  tag stig_id: 'DTAVSEL-109'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-68969r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

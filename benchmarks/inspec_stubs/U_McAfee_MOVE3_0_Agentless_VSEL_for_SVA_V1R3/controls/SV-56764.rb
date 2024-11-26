control 'SV-56764' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.0 Web UI must be disabled.'
  desc 'If the Web UI was left enabled, the system to which the VSEL has been installed would be vulnerable for Web attacks. Disabling the Web UI will prevent the system from listening on HTTP.'
  desc 'check', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "General Policies".

In the "Advanced" tab, verify the check box for "Disable client Web UI:" is selected.

If the check box for "Disable client Web UI:" is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the "Systems" tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "VirusScan Enterprise for Linux 1.9.0". From the "Policy" column, click on the policy for the "General Policies".

In the "Advanced" tab, select the check box for "Disable client Web UI:".

Click Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise for Linux (VSEL) 1.9'
  tag check_id: 'C-49429r2_chk'
  tag severity: 'medium'
  tag gid: 'V-43936'
  tag rid: 'SV-56764r1_rule'
  tag stig_id: 'DTAVSEL-109'
  tag gtitle: 'DTAVSEL-109-McAfee VSEL for SVA Web User Interface status'
  tag fix_id: 'F-49521r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

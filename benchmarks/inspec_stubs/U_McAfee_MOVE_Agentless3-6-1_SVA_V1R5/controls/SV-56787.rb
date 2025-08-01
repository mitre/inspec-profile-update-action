control 'SV-56787' do
  title 'The McAfee MOVE AV Agentless SVA policy must be configured with, and managed by, the HBSS ePO server.'
  desc 'Organizations should use centrally managed antivirus software that is controlled and monitored regularly by antivirus administrators, who are also typically responsible for acquiring, testing, approving, and delivering antivirus signature and software updates throughout the organization. Users should not be able to disable or delete antivirus software from their hosts, nor should they be able to alter critical settings. Antivirus administrators should perform continuous monitoring to confirm that hosts are using current antivirus software and that the software is configured properly. Implementing all of these recommendations should strongly support an organization in having a strong and consistent antivirus deployment across the organization.'
  desc 'check', 'NOTE: MOVE Agentless 3.61 Security Virtual Appliance (SVA) comes pre-installed with McAfee Agent 4.8 and requires that the McAfee Agent 4.8 Extension already be installed on the ePO 5.0.x Server. ePO 4.6 environments must upgrade to the McAfee Agent 4.8 Extension prior to deployment of the MOVE Agentless 3.61 SVA.

From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). 

If the system designated as the McAfee MOVE Security Virtual Appliance (SVA) is not in the ePO server System Tree, this is a finding.

If the system designated as the McAfee MOVE Security Virtual Appliance (SVA) is in the ePO server System Tree, click on the system to open the System Information page.

On the System Information page, verify "MOVE AV [Agentless]" is listed as an Installed Product.

If the system does not show MOVE AV [Agentless] listed as an installed product, this is a finding.'
  desc 'fix', 'Obtain the McAfee Agent install files from the McAfee ePO server and install onto the McAfee SVA, following the same procedures as for any other Linux system being managed by the McAfee ePO server.

After installation, from the ePO server console System Tree, select "My Organization". Select the Systems tab. Find and double-click on the asset representing the McAfee MOVE Security Virtual Appliance (SVA) to open its properties. 

Under the System Properties tab, ensure the "Last Communication" date is within the time period designated by the "Agent-to-Server Communication Interval:" under the McAfee Agent tab.

Under the System Properties tab, next to the Installed Products field, ensure MOVE AV [Agentless]" is listed as an installed product.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49406r4_chk'
  tag severity: 'medium'
  tag gid: 'V-43957'
  tag rid: 'SV-56787r2_rule'
  tag stig_id: 'AV-MOVE-SVA-001'
  tag gtitle: 'AV-MOVE-SVA-001-McAfee MOVE SVA policy management'
  tag fix_id: 'F-49400r6_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

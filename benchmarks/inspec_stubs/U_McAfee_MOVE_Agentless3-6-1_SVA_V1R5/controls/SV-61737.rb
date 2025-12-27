control 'SV-61737' do
  title 'The McAfee MOVE AV Agentless Scan policy must be configured to use McAfee Global Threat Intelligence file reputation set to a sensitivity level of Medium or higher.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since by querying the cloud-based database when a file appears to be suspicious, up-to-the-minute intelligence is provided. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'NOTE: This check is Not Applicable for SIPRNet systems.

From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select MOVE AV [Agentless] 3.6.1. Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "McAfee Global Threat Intelligence file reputation:", verify the "Sensitivity level:" is set to Medium, or higher.

If the "Sensitivity level:" for the "McAfee Global Threat Intelligence file reputation:" is not set to Medium, or higher, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select "My Organization". Select the Systems tab. To show all systems in the System Tree, select "This Group and All Subgroups" from the "Preset:" drop-down list. From the list of systems, locate the asset representing the McAfee MOVE Security Virtual Appliance (SVA). Click on the system to open the System Information page. 

Click on Actions | Agent | Modify Policies on a Single System. From the "Product:" drop-down list, select "MOVE AV [Agentless] 3.6.1". Locate "Scan" under the "Category" column and select the policy corresponding to it, found under the "Policy" column.

In the Scan Items tab of the Policy Settings, next to the "McAfee Global Threat Intelligence file reputation:", select Medium or higher from the "Sensitivity level:" drop-down list.

Click on Save.'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 3.0 SVA'
  tag check_id: 'C-49465r4_chk'
  tag severity: 'medium'
  tag gid: 'V-48859'
  tag rid: 'SV-61737r2_rule'
  tag stig_id: 'AV-MOVE-SVA-111'
  tag gtitle: 'AV-MOVE-SVA-111-McAfee MOVE GTI sensitivity level'
  tag fix_id: 'F-49577r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

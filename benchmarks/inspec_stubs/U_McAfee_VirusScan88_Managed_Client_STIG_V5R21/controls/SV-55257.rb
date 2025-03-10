control 'SV-55257' do
  title 'McAfee VirusScan Access Protection: Anti-Virus Standard Protection must be set to prevent IRC communication.'
  desc 'Internet Relay Chat (IRC) is the preferred communication method used by botnet herders and remote-access trojans to control botnets (a set of scripts or an independent program that connects to IRC). IRC allows an attacker to control infected machines that are sitting behind network address translation (NAT), and the bot can be configured to connect back to the command and control server listening on any port.'
  desc 'check', 'NOTE: If IRC Communication is enabled on a Classified network, in accordance with published Ports, Protocols, and Services Management (PPSM) guidelines, this requirement is not applicable.

NOTE: Since there is no HIPS signature to provide this same protection, this check is applicable even if HIPS is enabled.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Ensure both "Prevent IRC communication" (Block and Report) options are selected.

Criteria:  If both "Prevent IRC communication" (Block and Report) options are selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Ensure both "Prevent IRC communication" (Block and Report) options are selected.

Criteria:  If both "Prevent IRC communication" (Block and Report) options are selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Select both "Prevent IRC communication" (Block and Report) options. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48847r8_chk'
  tag severity: 'medium'
  tag gid: 'V-42529'
  tag rid: 'SV-55257r3_rule'
  tag stig_id: 'DTAM151'
  tag gtitle: 'DTAM151-Access Protection prevent IRC communication'
  tag fix_id: 'F-48111r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

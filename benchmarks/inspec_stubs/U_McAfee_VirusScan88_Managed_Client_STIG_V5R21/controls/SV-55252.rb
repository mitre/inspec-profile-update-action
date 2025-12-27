control 'SV-55252' do
  title 'McAfee VirusScan Access Protection: Common Standard Protection must be set to prevent hooking of McAfee processes.'
  desc "Hooking covers a range of techniques used to alter or augment the behavior of an operating system, of applications, or of other software components by intercepting function calls, messages, or events passed between software components. Code that handles such intercepted function calls, events, or messages is called a 'hook'. Hooking can also be used by malicious code. For example, rootkits, pieces of software that try to make themselves invisible by faking the output of API calls that would otherwise reveal their existence, often use hooking techniques. This rule prevents other processes from hooking of McAfee processes."
  desc 'check', 'Note: If the HIPS signature 6051 is enabled to provide this same protection, this check is not applicable. 

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Ensure both "Prevent hooking of McAfee processes" (Block and Report) options are selected.

Criteria:  If both "Prevent hooking of McAfee processes" (Block and Report) options are selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label.  In the "Categories" box, select "Common Standard Protection". Ensure both "Prevent hooking of McAfee processes" (Block and Report) options are both selected.

Criteria:  If "Prevent hooking of McAfee processes" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Select both "Prevent hooking of McAfee processes" (Block and Report) options. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48842r5_chk'
  tag severity: 'medium'
  tag gid: 'V-42524'
  tag rid: 'SV-55252r2_rule'
  tag stig_id: 'DTAM146'
  tag gtitle: 'DTAM146 - Access Protection prevent hooking of McAfee processes'
  tag fix_id: 'F-48106r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

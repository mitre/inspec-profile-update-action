control 'SV-216958' do
  title 'McAfee VirusScan Access Protection: Anti-Spyware Maximum Protection must be set to block and log execution of scripts from the Temp folder.'
  desc 'This rule prevents the Windows scripting host from running VBScript and JavaScript scripts from the Temp directory. This would protect against a large number of trojans and questionable web installation mechanisms that are used by many adware and spyware applications.'
  desc 'check', 'Note: If the HIPS signature 7035 is enabled to provide this same protection, this check is Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". Ensure the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected.

Criteria: If the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, access the local VirusScan console by clicking Start >> All Programs >> McAfee >> VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". Ensure the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected.

Criteria: If the "Prevent execution of scripts from the Temp folder" (Block and Report) option is selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. 

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Spyware Maximum Protection". 

Select the "Prevent execution of scripts from the Temp folder" (Block and Report) option. 

Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18188r309603_chk'
  tag severity: 'medium'
  tag gid: 'V-216958'
  tag rid: 'SV-216958r397873_rule'
  tag stig_id: 'DTAM148'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-18186r309604_fix'
  tag 'documentable'
  tag legacy: ['SV-55254', 'V-42526']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

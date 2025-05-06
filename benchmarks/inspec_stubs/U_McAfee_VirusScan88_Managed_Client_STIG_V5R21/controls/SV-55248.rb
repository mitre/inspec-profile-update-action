control 'SV-55248' do
  title 'McAfee VirusScan Access Protection: Common Standard Protection must be set to prevent modification of McAfee Common Management Agent files and settings.'
  desc "Many malicious programs have attempted to disable VirusScan by stopping services and processes and leaving the system vulnerable to attack. Self-protection is an important feature of VSE that prevents malicious programs from disabling VirusScan or any of its services or processes. Many trojans and viruses will attempt to terminate or even delete security products. VSE's self-protection features protect VirusScan registry values and processes from being altered or deleted by malicious code. This rule protects the McAfee security product from modification by any process not listed in the policy's exclusion list."
  desc 'check', 'Note: If the HIPS signature 3899 is enabled to provide this same protection, this check is not applicable. 

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Ensure both "Prevent modification of McAfee Common Management Agent files and settings" (Block and Report) options are selected.

Criteria:  If both "Prevent modification of McAfee Common Management Agent files and settings" (Block and Report) options are selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.

Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. 
In the "Categories" box, select "Common Standard Protection". 
Ensure "Prevent modification of McAfee Common Management Agent files and settings" (Block and Report) options are selected.

Criteria:  If "Prevent modification of McAfee Common Management Agent files and settings" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Select both "Prevent modification of McAfee Common Management Agent files and settings" (Block and Report) options. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48838r6_chk'
  tag severity: 'medium'
  tag gid: 'V-42520'
  tag rid: 'SV-55248r2_rule'
  tag stig_id: 'DTAM142'
  tag gtitle: 'DTAM142 - Access Protection preventing modification of McAfee CMA'
  tag fix_id: 'F-48102r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

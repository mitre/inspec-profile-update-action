control 'SV-216959' do
  title 'McAfee VirusScan Access Protection: Anti-Virus Standard Protection must be set to prevent remote creation of autorun files.'
  desc 'Autorun files are used to automatically launch program files, typically setup files from CDs. Preventing other computers from making a connection and creating or altering autorun.inf files can prevent spyware and adware from being executed. There are many spyware and virus programs distributed on CDs.'
  desc 'check', 'Note: If the HIPS signature 3886 is enabled to provide this same protection, this check is Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Ensure both "Prevent remote creation of autorun files" (Block and Report) options are selected.

Criteria:  If both "Prevent remote creation of autorun files" (Block and Report) options are selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. 
In the "Categories" box, select "Anti-Virus Standard Protection". 
Ensure "Prevent remote creation of autorun files" (Block and Report) options are both selected.

Criteria:  If "Prevent remote creation of autorun files" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Select both "Prevent remote creation of autorun files" (Block and Report) options. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18189r309606_chk'
  tag severity: 'medium'
  tag gid: 'V-216959'
  tag rid: 'SV-216959r397870_rule'
  tag stig_id: 'DTAM149'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18187r309607_fix'
  tag 'documentable'
  tag legacy: ['SV-55255', 'V-42527']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

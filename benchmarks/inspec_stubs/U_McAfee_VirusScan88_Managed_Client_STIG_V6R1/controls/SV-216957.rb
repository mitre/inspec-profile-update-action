control 'SV-216957' do
  title 'McAfee VirusScan Access Protection: Common Maximum Protection must be set to detect and log launching of files from the Downloaded Programs Files folder.'
  desc 'A common distribution method for adware and spyware is to have the user download an executable file and run it automatically from the Downloaded Program Files folder. This rule is specific to Microsoft Internet Explorer and prevents software installations through the web browser. Internet Explorer runs code from the Downloaded Program Files directory, notably ActiveX controls. Some vulnerabilities in Internet Explorer and viruses place an .exe file into this directory and run it. This rule closes that attack vector.'
  desc 'check', 'Note: If the HIPS signature 3910 is enabled to provide this same protection, this check is not applicable. 

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Maximum Protection". Ensure the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected.

Criteria:  If the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected, this is not a finding.

Registry keys are not available for this setting. 

To validate from client side, access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Maximum Protection". Ensure the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected.

Criteria:  If the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Access Protection Policies. Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Maximum Protection". Select the "Prevent launching of files from the Downloaded Program Files folder" (Report) option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18187r309600_chk'
  tag severity: 'medium'
  tag gid: 'V-216957'
  tag rid: 'SV-216957r397645_rule'
  tag stig_id: 'DTAM147'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-18185r309601_fix'
  tag 'documentable'
  tag legacy: ['SV-55253', 'V-42525']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end

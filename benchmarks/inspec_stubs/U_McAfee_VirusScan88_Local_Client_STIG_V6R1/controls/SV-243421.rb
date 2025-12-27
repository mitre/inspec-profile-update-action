control 'SV-243421' do
  title 'McAfee VirusScan Access Protection Rules Common Maximum Protection must be set to detect and log the launching of files from the Downloaded Programs Files folder.'
  desc 'A common distribution method for adware and spyware is to have the user download an executable file and run it automatically from the Downloaded Program Files folder. This rule is specific to Microsoft Internet Explorer and prevents software installations through the web browser. Internet Explorer runs code from the Downloaded Program Files directory, notably ActiveX controls. Some vulnerabilities in Internet Explorer and viruses place an .exe file into this directory and run it. This rule closes that attack vector.'
  desc 'check', 'Note: If the HIPS signature 3910 is enabled to provide this same protection, this check is not applicable. 

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Maximum Protection". Ensure the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected.

Criteria:  If the "Prevent launching of files from the Downloaded Program Files folder" (Report) option is selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Maximum Protection". Select the "Prevent launching of files from the Downloaded Program Files folder" (Report) option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46696r722600_chk'
  tag severity: 'medium'
  tag gid: 'V-243421'
  tag rid: 'SV-243421r722602_rule'
  tag stig_id: 'DTAM147'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-46653r722601_fix'
  tag 'documentable'
  tag legacy: ['V-6617', 'SV-56414']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end

control 'SV-55288' do
  title 'McAfee VirusScan Access Protection Rules Anti-Virus Standard Protection must be set to prevent remote creation of autorun files.'
  desc 'Autorun files are used to automatically launch program files, typically setup files from CDs. Preventing other computers from making a connection and creating or altering autorun.inf files can prevent spyware and adware from being executed. There are many spyware and virus programs distributed on CDs.'
  desc 'check', 'Note: If the HIPS signature 3886 is enabled to provide this same protection, this check is Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. 
In the "Categories" box, select "Anti-Virus Standard Protection". 
Ensure "Prevent remote creation of autorun files" (Block and Report) options are both selected.

Criteria:  If "Prevent remote creation of autorun files" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". 
Select "Prevent remote creation of autorun files" (Block and Report) options. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49360r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42560'
  tag rid: 'SV-55288r2_rule'
  tag stig_id: 'DTAM149'
  tag gtitle: 'DTAM149 - Access Protection prevent remote creation of autorun files'
  tag fix_id: 'F-48142r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

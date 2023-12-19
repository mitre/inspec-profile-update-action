control 'SV-55280' do
  title 'McAfee VirusScan Access Protection Rules Common Standard Protection must be set to prevent modification of McAfee files and settings.'
  desc "Many malicious programs have attempted to disable VirusScan by stopping services and processes and leaving the system vulnerable to attack. Self-protection is an important feature of VSE that prevents malicious programs from disabling VirusScan or any of its services or processes. Many trojans and viruses will attempt to terminate or even delete security products. VSE's self-protection features protect VirusScan registry values and processes from being altered or deleted by malicious code. This rule protects the McAfee security product from modification by any process not listed in the policy's exclusion list."
  desc 'check', 'Note: If the HIPS signature 3898 is enabled to provide this same protection, this check is not applicable. 

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. 
In the "Categories" box, select "Common Standard Protection". 
Ensure "Prevent modification of McAfee files and settings" (Block and Report) options are selected.

Criteria:  If "Prevent modification of McAfee files and settings" (Block and Report) options are both selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. 
In the "Categories" box, select "Common Standard Protection". 
Select "Prevent modification of McAfee files and settings" (Block and Report) options. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49352r3_chk'
  tag severity: 'medium'
  tag gid: 'V-42552'
  tag rid: 'SV-55280r2_rule'
  tag stig_id: 'DTAM141'
  tag gtitle: 'DTAM141 - Access Protection prevent modification of McAfee files and settings'
  tag fix_id: 'F-48134r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

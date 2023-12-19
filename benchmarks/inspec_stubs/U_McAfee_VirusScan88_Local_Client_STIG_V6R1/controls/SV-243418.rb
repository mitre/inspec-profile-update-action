control 'SV-243418' do
  title 'McAfee VirusScan Access Protection Rules Common Standard Protection must be set to prevent termination of McAfee processes.'
  desc "Many malicious programs have attempted to disable VirusScan by stopping services and processes and leaving the system vulnerable to attack. Self-protection is an important feature of VSE that prevents malicious programs from disabling VirusScan or any of its services or processes. Many trojans and viruses will attempt to terminate or even delete security products. VSE's self-protection features protect VirusScan registry values and processes from being altered or deleted by malicious code. This rule protects the McAfee security product from modification by any process not listed in the policy's exclusion list."
  desc 'check', 'Note: If the HIPS signature 3892 is enabled to provide this same protection, this check is not applicable. 

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Ensure both "Prevent termination of McAfee processes" (Block and Report) options are selected.

Criteria:  If both "Prevent termination of McAfee processes" (Block and Report) options are selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Common Standard Protection". Select "Prevent termination of McAfee processes" (Block and Report) options. 

Click OK to save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46693r722591_chk'
  tag severity: 'medium'
  tag gid: 'V-243418'
  tag rid: 'SV-243418r722593_rule'
  tag stig_id: 'DTAM144'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-46650r722592_fix'
  tag 'documentable'
  tag legacy: ['V-42576', 'SV-55304']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

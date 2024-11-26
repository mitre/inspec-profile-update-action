control 'SV-243425' do
  title 'McAfee VirusScan Access Protection Rules Anti-Virus Standard Protection must be set to prevent IRC communication.'
  desc 'Internet Relay Chat (IRC) is the preferred communication method used by botnet herders and remote-access trojans to control botnets (a set of scripts or an independent program that connects to IRC). IRC allows an attacker to control infected machines that are sitting behind network address translation (NAT), and the bot can be configured to connect back to the command and control server listening on any port.'
  desc 'check', 'NOTE: If IRC Communication is enabled on a Classified network, in accordance with published Ports, Protocols, and Services Management (PPSM) guidelines, this requirement is not applicable.

NOTE: Since there is no HIPS signature to provide this same protection, this check is applicable even if HIPS is enabled.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Ensure both "Prevent IRC communication" (Block and Report) options are selected.

Criteria:  If both "Prevent IRC communication" (Block and Report) options are selected, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
Under the Task column, select Access Protection, right-click, and select Properties.

Under the Access Protection tab, locate the "Access protection rules:" label. In the "Categories" box, select "Anti-Virus Standard Protection". Select both "Prevent IRC communication" (Block and Report) options. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46700r722612_chk'
  tag severity: 'medium'
  tag gid: 'V-243425'
  tag rid: 'SV-243425r722614_rule'
  tag stig_id: 'DTAM151'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-46657r722613_fix'
  tag 'documentable'
  tag legacy: ['V-42514', 'SV-55227']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end

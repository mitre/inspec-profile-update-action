control 'SV-243382' do
  title 'McAfee VirusScan On-Demand scan must be configured to find unknown program threats.'
  desc 'Due to the ability of malware to mutate after infection, standard antivirus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', %q(Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Heuristics: " label. Ensure the "Find unknown program threats" option is selected.

Criteria:  If "Find unknown program threats" is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\Software\McAfee\ (32-bit)
HKLM\Software\Wow6432Node\McAfee\ (64-bit)
DesktopProtection\Tasks

Under the DesktopProtection\Tasks, and with the assistance of the System Administrator, review each GUID key's szTaskName to find the GUID key associated with weekly on-demand client scan task. 

Criteria:  If, under the applicable GUID key, the dwProgramHeuristicsLevel has value of 0, this is a finding.)
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, with the assistance of the System Administrator, identify the weekly on-demand client scan task. 
Right-click the Task and select Properties.

Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown program threats" option. 


Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46657r722483_chk'
  tag severity: 'medium'
  tag gid: 'V-243382'
  tag rid: 'SV-243382r722485_rule'
  tag stig_id: 'DTAM054'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-46614r722484_fix'
  tag 'documentable'
  tag legacy: ['V-14654', 'SV-56416']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end

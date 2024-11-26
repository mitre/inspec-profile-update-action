control 'SV-243400' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to find unknown macro viruses.'
  desc 'Due to the ability of malware to mutate after infection, standard antivirus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console
On the menu bar, click Task->On-Access Scanner Properties.
Under the Scan Items tab, locate the "Heuristics:" label. Ensure the "Find unknown macro threats" option is selected.

Criteria:  If the "Find unknown macro threats" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value dwMacroHeuristicsLevel is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console. 
Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown macro threats" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46675r722537_chk'
  tag severity: 'medium'
  tag gid: 'V-243400'
  tag rid: 'SV-243400r722539_rule'
  tag stig_id: 'DTAM105'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46632r722538_fix'
  tag 'documentable'
  tag legacy: ['V-14626', 'SV-56431']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

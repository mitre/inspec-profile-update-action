control 'SV-216935' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to find unknown unwanted programs and trojans.'
  desc 'Due to the ability of malware to mutate after infection, standard antivirus signatures may not be able to catch new strains or variants of the malware. Typically, these strains and variants will share unique characteristics with others in their virus family. By using a generic signature to detect the shared characteristics, using wildcards where differences lie, the generic signature can detect viruses even if they are padded with extra, meaningless code. This method of detection is Heuristic detection.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Heuristics:" label. Ensure the "Find unknown unwanted program threats and trojans" option is selected.

Criteria:  If the "Find unknown unwanted programs and trojans" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value dwProgramHeuristicsLevel is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Heuristics:" label. Select the "Find unknown unwanted programs and trojans" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18165r309534_chk'
  tag severity: 'medium'
  tag gid: 'V-216935'
  tag rid: 'SV-216935r397870_rule'
  tag stig_id: 'DTAM104'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18163r309535_fix'
  tag 'documentable'
  tag legacy: ['SV-55230', 'V-14626']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

control 'SV-243398' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to scan all files.'
  desc 'When scanning for malware, excluding specific file types will increase the risk of a malware-infected file going undetected. By configuring antivirus software to scan all file types, the scanner has a higher success rate at detecting and eradicating malware.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "What to scan:" label. Ensure the "All Files" radio button is selected.

Criteria:  If the "All Files" radio button is selected, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value LocalExtensionMode is 1 and the value of NetworkExtensionMode is 1 this is not a finding. If either of these is not 1, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "What to scan:" label. Select the "All Files" radio button option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46673r722531_chk'
  tag severity: 'medium'
  tag gid: 'V-243398'
  tag rid: 'SV-243398r722533_rule'
  tag stig_id: 'DTAM103'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46630r722532_fix'
  tag 'documentable'
  tag legacy: ['V-14624', 'SV-56429']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

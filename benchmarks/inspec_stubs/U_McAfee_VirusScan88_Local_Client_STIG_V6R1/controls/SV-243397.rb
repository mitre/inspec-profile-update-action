control 'SV-243397' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to scan when reading from disk.'
  desc 'Antivirus software is the most commonly used technical control for malware threat mitigation. Real-time scanning of files as they are read from disk is a crucial first line of defense from malware attacks.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Scan files:" label. Ensure the "When reading from disk" is selected.

Criteria:  If the "When reading from disk" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value bScanOutgoing is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Scan files:" label. Select the "When reading from disk" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46672r722528_chk'
  tag severity: 'medium'
  tag gid: 'V-243397'
  tag rid: 'SV-243397r722530_rule'
  tag stig_id: 'DTAM102'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46629r722529_fix'
  tag 'documentable'
  tag legacy: ['V-14623', 'SV-56413']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

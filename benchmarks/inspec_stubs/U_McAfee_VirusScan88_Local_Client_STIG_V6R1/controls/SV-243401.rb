control 'SV-243401' do
  title 'McAfee VirusScan On-Access Scanner All Processes settings must be configured to scan inside archive files.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'NOTE: This requirement can be left not configured and marked as Not Applicable if the regularly scheduled on-demand scan, validated under V-6611, DTAM052, includes the scanning of archive files.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Compressed files:" label. Ensure the "Scan inside archives (e.g., .ZIP)" option is selected.

Criteria:  If the "Scan inside archives (e.g., .ZIP)" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value ScanArchives is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select All Processes.

Under the Scan Items tab, locate the "Compressed files:" label. Select the "Scan inside archives (e.g., .ZIP)" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46676r722540_chk'
  tag severity: 'medium'
  tag gid: 'V-243401'
  tag rid: 'SV-243401r722542_rule'
  tag stig_id: 'DTAM106'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46633r722541_fix'
  tag 'documentable'
  tag legacy: ['V-14627', 'SV-56432']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

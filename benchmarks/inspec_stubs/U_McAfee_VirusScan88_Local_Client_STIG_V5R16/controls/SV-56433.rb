control 'SV-56433' do
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
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49338r4_chk'
  tag severity: 'medium'
  tag gid: 'V-14628'
  tag rid: 'SV-56433r3_rule'
  tag stig_id: 'DTAM106'
  tag gtitle: 'DTAM106-McAfee VirusScan scan inside archive'
  tag fix_id: 'F-49142r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

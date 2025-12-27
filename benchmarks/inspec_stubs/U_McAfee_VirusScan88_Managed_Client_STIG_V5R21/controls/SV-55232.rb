control 'SV-55232' do
  title 'McAfee VirusScan On-Access Default Processes Policies must be configured to scan inside archives.'
  desc 'Malware is often packaged within an archive. In addition, archives might have other archives within. Not scanning archive files introduces the risk of infected files being introduced into the environment.'
  desc 'check', 'NOTE: This requirement can be left not configured and marked as Not Applicable if the regularly scheduled on-demand scan, as validated under V-6611, DTAM052, includes the scanning of archive files.

From the ePO server console System Tree, select the "Systems" tab, select the asset to be checked, select "Actions", select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Compressed files:" label. Ensure the "Scan inside archives (e.g. .ZIP)" option is selected.

Criteria:  If the "Scan inside archives (e.g. .ZIP)" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the value ScanArchives is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. Under the Scan Items tab, locate the "Compressed files:" label. Select the "Scan inside archives (e.g. .ZIP)" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48822r5_chk'
  tag severity: 'medium'
  tag gid: 'V-14628'
  tag rid: 'SV-55232r3_rule'
  tag stig_id: 'DTAM106'
  tag gtitle: 'DTAM106-McAfee VirusScan scan inside archive'
  tag fix_id: 'F-48087r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

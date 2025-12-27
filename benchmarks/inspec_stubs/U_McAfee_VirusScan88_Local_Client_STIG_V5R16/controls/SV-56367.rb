control 'SV-56367' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to scan boot sectors.'
  desc 'Boot sector viruses will install into the boot sector of a system, ensuring that they will execute when the user boots the system. This risk is mitigated by scanning boot sectors at each startup of the system.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties
Select the General Settings.

Under the General tab, locate the "Scan:" label. Ensure the "Boot Sectors" option is selected.

Criteria:  If the "Boot Sectors" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit) 
\\SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bDontScanBootSectors is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings. 

Under the General tab, locate the "Scan:" label. Select the "Boot Sectors" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49291r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6467'
  tag rid: 'SV-56367r1_rule'
  tag stig_id: 'DTAM002'
  tag gtitle: 'DTAM002-McAfee VirusScan on access scan boot sectors'
  tag fix_id: 'F-49048r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

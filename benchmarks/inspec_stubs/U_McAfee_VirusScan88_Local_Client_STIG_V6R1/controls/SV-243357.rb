control 'SV-243357' do
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
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46632r722408_chk'
  tag severity: 'medium'
  tag gid: 'V-243357'
  tag rid: 'SV-243357r722410_rule'
  tag stig_id: 'DTAM002'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46589r722409_fix'
  tag 'documentable'
  tag legacy: ['V-42571', 'SV-55299']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

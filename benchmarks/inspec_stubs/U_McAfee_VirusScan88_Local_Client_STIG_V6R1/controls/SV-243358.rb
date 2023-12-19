control 'SV-243358' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to scan floppy during shutdown.'
  desc 'Computer viruses in the early days of personal computing were almost exclusively passed around by floppy disks. Floppy disks would be used to boot the computer and, if infected, would infect the hard drive files, as well. Although floppy drives have fallen out of use, it is still a good security practice, whenever the antivirus software allows, to enable the scanning software to scan a floppy disk at shutdown.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the General tab, locate the "Scan:" label. Ensure the "Floppy during shutdown" option is selected.

Criteria:  If the "Floppy during shutdown" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit) 
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\

Criteria:  If the value of bScanFloppyonShutdown is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the General tab, locate the "Scan:" label. Select the "Floppy during shutdown" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46633r722411_chk'
  tag severity: 'medium'
  tag gid: 'V-243358'
  tag rid: 'SV-243358r722413_rule'
  tag stig_id: 'DTAM003'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46590r722412_fix'
  tag 'documentable'
  tag legacy: ['V-6597', 'SV-56393']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

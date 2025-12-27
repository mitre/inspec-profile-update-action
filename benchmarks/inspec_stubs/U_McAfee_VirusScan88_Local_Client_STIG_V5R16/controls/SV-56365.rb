control 'SV-56365' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to enable on-access scanning at system startup.'
  desc "For Antivirus software to be effective, it must be running at all times, beginning from the point of the system's initial startup. Otherwise, the risk is greater for viruses, trojans, and other malware infecting the system during that startup phase."
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.
Under the General tab, locate the "General:" label. Ensure the "Enable on-access scanning at system startup" option is selected.

Criteria:  If the "Enable on-access scanning at startup" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
\\SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of bStartDisabled is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties. 

Under the General tab, locate the "General:" label. Select the "Enable on-access scanning at system startup" option. 

Click OK to Save.'
  impact 0.7
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49292r2_chk'
  tag severity: 'high'
  tag gid: 'V-6453'
  tag rid: 'SV-56365r1_rule'
  tag stig_id: 'DTAM001'
  tag gtitle: 'DTAM001-McAfee VirusScan Control Panel'
  tag fix_id: 'F-49116r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

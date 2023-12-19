control 'SV-56370' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to prevent users from removing messages from the list.'
  desc 'Good incident response analysis includes reviewing all logs and alerts on the system reporting the infection. If users were permitted to remove alerts from the display, incident response forensic analysis would be inhibited.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Messages tab, locate the "Actions available to user:" label. Ensure the "Remove messages from the list" option is NOT selected.

Criteria:  If the "Remove messages from the list" option is NOT selected, this is not a finding. 

On the client machine use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit) 
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria: If the value of Alert_UsersCanRemove is 0, this is not a finding. If the value is 1, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click on Task->On-Access Scanner Properties.
Select the General Settings.

Under the Messages tab, locate the "Actions available to user:" label. Uncheck the "Remove messages from the list" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49296r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6470'
  tag rid: 'SV-56370r1_rule'
  tag stig_id: 'DTAM005'
  tag gtitle: 'DTAM005-McAfee VirusScan remove messages'
  tag fix_id: 'F-49052r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

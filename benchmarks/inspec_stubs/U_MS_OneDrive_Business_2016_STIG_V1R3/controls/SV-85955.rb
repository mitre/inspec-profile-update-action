control 'SV-85955' do
  title 'Users must be prevented from configuring personal OneDrive accounts.'
  desc 'This policy setting allows you to prevent users from configuring a personal OneDrive account on the machine. If users had previously added a personal OneDrive account to the machine they will be shown an error the next time that they start the client.'
  desc 'check', 'Note: It is important to load the OneDrive ADMX/L templates under the DISA GPO Baseline Package under the ADMX Templates\\OneDrive NextGen in order to view and set the settings appropriately. The DISA GPO Baseline Package can be downloaded from the DoD Cyber Exchange.

Verify the policy value for User Configuration -> Administrative Templates -> OneDrive -> "Prevent users from configuring personal OneDrive accounts" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\SOFTWARE\\Microsoft\\OneDrive
Criteria: If the value DisablePersonalSync is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> OneDrive -> "Prevent users from configuring personal OneDrive acccounts" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive 2016'
  tag check_id: 'C-71731r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71331'
  tag rid: 'SV-85955r3_rule'
  tag stig_id: 'DTOO604'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77643r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

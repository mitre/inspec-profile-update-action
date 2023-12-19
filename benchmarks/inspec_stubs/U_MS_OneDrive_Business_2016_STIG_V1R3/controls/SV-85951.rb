control 'SV-85951' do
  title 'Users must be prevented from using the remote fetch feature to access files on the machine (64 bit).'
  desc 'This setting will prevent users from going to onedrive.com to use the remote fetch feature to browse the file system of the machine (a feature supported on OneDrive running on Windows with the exception of Windows 8.1). This setting is for machines running 64-bit versions of Windows.'
  desc 'check', 'Note: It is important to load the OneDrive ADMX/L templates under the DISA GPO Baseline Package under the ADMX Templates\\OneDrive NextGen in order to view and set the settings appropriately. The DISA GPO Baseline Package can be downloaded from the DoD Cyber Exchange.

Verify the policy value for Computer Configuration -> Administrative Templates -> OneDrive -> "Prevent users from using the remote fetch feature to access files on the machine (64-bit)" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Wow6432Node\\Microsoft\\OneDrive\\Remote Access
Criteria: If the value GPOEnabled is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> OneDrive -> "Prevent users from using the remote fetch feature to access files on the machine (64-bit)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft OneDrive 2016'
  tag check_id: 'C-71725r11_chk'
  tag severity: 'medium'
  tag gid: 'V-71327'
  tag rid: 'SV-85951r2_rule'
  tag stig_id: 'DTOO603'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77635r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

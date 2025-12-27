control 'SV-224955' do
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Web-based programs may attempt to install malicious software on a system. Ensuring users are notified if a web-based program attempts to install software allows them to refuse the installation.'
  desc 'check', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

If the registry value name below does not exist, this is not a finding.

If it exists and is configured with a value of "0", this is not a finding.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Value Type: REG_DWORD
Value: 0x00000000 (0) (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26646r465767_chk'
  tag severity: 'medium'
  tag gid: 'V-224955'
  tag rid: 'SV-224955r569186_rule'
  tag stig_id: 'WN16-CC-000470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26634r465768_fix'
  tag 'documentable'
  tag legacy: ['SV-88251', 'V-73587']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-253412' do
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Web-based programs may attempt to install malicious software on a system. Ensuring users are notified if a web-based program attempts to install software allows them to refuse the installation.'
  desc 'check', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

If it exists and is configured with a value of "1", this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: SafeForScripting

Value Type: REG_DWORD
Value: 0 (or if the Value Name does not exist)'
  desc 'fix', 'The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation when a web-based program attempts to install software on the system.

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56865r829318_chk'
  tag severity: 'medium'
  tag gid: 'V-253412'
  tag rid: 'SV-253412r829320_rule'
  tag stig_id: 'WN11-CC-000320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56815r829319_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-226215' do
  title 'Windows Media Player must be configured to prevent automatic checking for updates.'
  desc 'Uncontrolled system updates can introduce issues to a system.  The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\\untested software on the system.'
  desc 'check', 'Windows Media Player is not installed by default.  If it is not installed, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: DisableAutoupdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'If Windows Media Player is installed, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Prevent Automatic Updates" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27917r475968_chk'
  tag severity: 'medium'
  tag gid: 'V-226215'
  tag rid: 'SV-226215r852115_rule'
  tag stig_id: 'WN12-CC-000122'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27905r475969_fix'
  tag 'documentable'
  tag legacy: ['SV-53130', 'V-3480']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end

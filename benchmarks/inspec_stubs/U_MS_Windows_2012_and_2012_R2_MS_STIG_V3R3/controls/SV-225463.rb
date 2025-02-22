control 'SV-225463' do
  title 'The Ctrl+Alt+Del security attention sequence for logons must be enabled.'
  desc "Disabling the Ctrl+Alt+Del security attention sequence can compromise system security.  Because only Windows responds to the Ctrl+Alt+Del security sequence, a user can be assured that any passwords entered following that sequence are sent only to Windows.  If the sequence requirement is eliminated, malicious programs can request and receive a user's Windows password.  Disabling this sequence also suppresses a custom logon banner."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DisableCAD

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Do not require CTRL+ALT+DEL" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27162r471731_chk'
  tag severity: 'medium'
  tag gid: 'V-225463'
  tag rid: 'SV-225463r569185_rule'
  tag stig_id: 'WN12-SO-000019'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27150r471732_fix'
  tag 'documentable'
  tag legacy: ['SV-52866', 'V-1154']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

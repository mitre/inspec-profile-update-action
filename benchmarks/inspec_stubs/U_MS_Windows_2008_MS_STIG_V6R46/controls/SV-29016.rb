control 'SV-29016' do
  title 'Ctrl+Alt+Del security attention sequence is Disabled.'
  desc 'Disabling the Ctrl+Alt+Del security attention sequence can compromise system security.  Because only Windows responds to the Ctrl+Alt+Del security sequence, you can be assured that any passwords you enter following that sequence are sent only to Windows.  If you eliminate the sequence requirement, malicious programs can request and receive your Windows password.  Disabling this sequence also suppresses a custom logon banner.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Interactive Logon: Do not require CTRL+ALT+DEL” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  DisableCAD

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive Logon: Do not require CTRL ALT DEL” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-88r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1154'
  tag rid: 'SV-29016r1_rule'
  tag gtitle: 'Ctrl+Alt+Del Security Attention Sequence'
  tag fix_id: 'F-92r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

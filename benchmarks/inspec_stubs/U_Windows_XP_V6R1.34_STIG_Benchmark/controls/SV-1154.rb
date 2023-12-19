control 'SV-1154' do
  title 'Ctrl+Alt+Del security attention sequence is Disabled.'
  desc 'Disabling the Ctrl+Alt+Del security attention sequence can compromise system security.  Because only Windows responds to the Ctrl+Alt+Del security sequence, you can be assured that any passwords you enter following that sequence are sent only to Windows.  If you eliminate the sequence requirement, malicious programs can request and receive your Windows password.  Disabling this sequence also suppresses a custom logon banner.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive Logon: Do not require CTRL ALT DEL” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1154'
  tag rid: 'SV-1154r1_rule'
  tag gtitle: 'Ctrl+Alt+Del Security Attention Sequence'
  tag fix_id: 'F-92r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end

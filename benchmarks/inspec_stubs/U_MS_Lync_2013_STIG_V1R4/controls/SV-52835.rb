control 'SV-52835' do
  title 'Session Initiation Protocol (SIP) security mode must be configured.'
  desc 'Lync 2013 provides a single, unified client for real-time communications, including voice and video calls, Lync Meetings, presence, instant messaging, and persistent chat, using the Session Initiation Protocol (SIP). SIP is widely used for controlling multimedia communication sessions, such as voice and video calls over Internet Protocol (IP) networks. By using TLS it would render a sniff/man in the middle attack very difficult to impossible to achieve within the time period in which a given conversation could be attacked. TLS authenticates all parties and encrypts all traffic. This does not prevent listening over the wire, but the attacker cannot read the traffic unless the encryption is broken.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Configure SIP security mode" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\15.0\\lync

Criteria: If the value enablesiphighsecuritymode is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Configure SIP security mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Lync 2013'
  tag check_id: 'C-47152r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40777'
  tag rid: 'SV-52835r1_rule'
  tag stig_id: 'DTOO421'
  tag gtitle: 'DTOO421 - Session Initiation Protocol (SIP) security mode'
  tag fix_id: 'F-45761r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

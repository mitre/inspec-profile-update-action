control 'SV-52836' do
  title 'In the event a secure Session Initiation Protocol (SIP) connection fails, the connection must be restricted from resorting to the unencrypted HTTP.'
  desc 'Lync 2013 provides a single, unified client for real-time communications, including voice and video calls, Lync Meetings, presence, instant messaging, and persistent chat. The Lync client has a fall back option so that, in the event the Lync client cannot make a secure SIP connection to the Lync server, it will fall back to an unencrypted HTTP connection. In that event, all traffic will be unencrypted and in clear text. The configuration must be set to prevent HTTP being used for SIP connections in the event TLS or TCP fail.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\15.0\\lync

Criteria: If the value disablehttpconnect is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Lync 2013'
  tag check_id: 'C-47153r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40778'
  tag rid: 'SV-52836r2_rule'
  tag stig_id: 'DTOO422'
  tag gtitle: 'DTOO422 - Session Initiation Protocol (SIP)'
  tag fix_id: 'F-45762r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

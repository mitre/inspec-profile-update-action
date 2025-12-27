control 'SV-52834' do
  title 'The ability of Lync to store user passwords must be disabled.'
  desc 'Lync 2013 provides a single, unified client for real-time communications, including voice and video calls, Lync Meetings, presence, instant messaging, and persistent chat. These features require the ability to log into the service with a username and password. The Lync client could potentially be configured to store user passwords locally which would allow it to be susceptible to compromise and to be used maliciously.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Allow storage of user passwords" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\15.0\\lync

Criteria: If the value savepassword is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Lync 2013 -> Microsoft Lync Feature Policies "Allow storage of user passwords" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Lync 2013'
  tag check_id: 'C-47151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40776'
  tag rid: 'SV-52834r1_rule'
  tag stig_id: 'DTOO420'
  tag gtitle: 'DTOO420 - Store user passwords'
  tag fix_id: 'F-45760r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

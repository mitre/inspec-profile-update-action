control 'SV-80457' do
  title 'Trend Deep Security must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse, and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Review the Trend Deep Security server to ensure the execution of privileged functions are audited.

Interview the ISSO for a list of functions identified as privileged within the application “System Events.” Privileged functions within the system events will include but are not limited to: Computer Created, Computer Deleted, User Added, etc.). 

Verify the list against the Administration >> System Settings >> System Events tab. 

If the events are not to Record and Forward, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to audit the execution of privileged functions.

Enable the necessary privileged functions by selecting “Record” and “Forward” within the Administration >> System Settings >> System Events tab.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65967'
  tag rid: 'SV-80457r1_rule'
  tag stig_id: 'TMDS-00-000255'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-72043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end

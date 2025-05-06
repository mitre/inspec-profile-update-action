control 'SV-202086' do
  title 'The network device must display an explicit logout message to administrators indicating the reliable termination of authenticated communications sessions.'
  desc 'If an explicit logout message is not displayed and the administrator does not expect to see one, the administrator may inadvertently leave a management session un-terminated. The session may remain open and be exploited by an attacker; this is referred to as a zombie session. Administrators need to be aware of whether or not the session has been terminated.

A prompt for new logon is an acceptable indication of previous session termination. If the device takes the user back to the logon page or prompt after selecting the logoff button, it is considered an explicit logout message. In the case of terminal sessions (such as SSH), an explicit logoff message is displayed by the client application. Usually this is a message such as "connect closed by remote host" displayed by the client. For a terminal connected to the console port of a network device, either a logoff message is displayed or the device takes the user back to the logon prompt.'
  desc 'check', 'This requirement may be verified by demonstration. If an explicit logoff message is not displayed, or provides clear evidence that the session has been terminated, this is a finding.'
  desc 'fix', 'Configure the network device to display an explicit logoff message to administrators indicating the reliable termination of authenticated communications sessions. This may be a capability the device is inherently capable of.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2212r381860_chk'
  tag severity: 'medium'
  tag gid: 'V-202086'
  tag rid: 'SV-202086r879675_rule'
  tag stig_id: 'SRG-APP-000297-NDM-000281'
  tag gtitle: 'SRG-APP-000297'
  tag fix_id: 'F-2213r381861_fix'
  tag 'documentable'
  tag legacy: ['SV-69445', 'V-55199']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end

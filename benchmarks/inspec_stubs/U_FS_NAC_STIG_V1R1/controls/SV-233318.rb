control 'SV-233318' do
  title 'Forescout must place client machines on the blacklist and terminate Forescout agent connection when critical security issues are found that put the network at risk.'
  desc 'If a device communicates outside of its normal required communication, this could be suspect traffic and should be stopped and proper individuals notified immediately.'
  desc 'check', 'Check Forescout policy to ensure that any device with a critical security issue is checked through a security policy and an action is taken to either blacklist it or terminate communication with other network devices.

If the NAC does not immediately place the device on the blacklist and terminate the connection when critical security issues are found that put the network at immediate risk, this a finding.'
  desc 'fix', 'Login to the Forescout UI.
 
1. From the Policy tab, identify a Compliance policy.
2. Within the Compliance policy, under Sub-Rule for a device with critical security issues, ensure that an action that Adds Device to Blacklist and/or Disables Device, is enabled.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36513r605657_chk'
  tag severity: 'high'
  tag gid: 'V-233318'
  tag rid: 'SV-233318r611394_rule'
  tag stig_id: 'FORE-NC-000100'
  tag gtitle: 'SRG-NET-000015-NAC-000120'
  tag fix_id: 'F-36478r605658_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

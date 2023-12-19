control 'SV-235774' do
  title 'The built-in DNS client must be disabled.'
  desc 'This setting controls whether to use the built-in DNS client.

This does not affect which DNS servers are used; it only controls the software stack that is used to communicate with them. For example, if the operating system is configured to use an enterprise DNS server, that same server would be used by the built-in DNS client. However, it is however possible that the built-in DNS client will address servers in different ways by using more modern DNS-related protocols such as DNS-over-TLS.

If this policy is enabled, the built-in DNS client is used if it is available.

If this policy is disabled, the client is never used.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Use built-in DNS client" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "BuiltInDnsClientEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Use built-in DNS client" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38993r626518_chk'
  tag severity: 'medium'
  tag gid: 'V-235774'
  tag rid: 'SV-235774r626523_rule'
  tag stig_id: 'EDGE-00-000062'
  tag gtitle: 'SRG-APP-000157'
  tag fix_id: 'F-38956r626519_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end

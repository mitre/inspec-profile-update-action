control 'SV-90943' do
  title 'The network device must be configured to use a centralized authentication server to authenticate privileged users for remote and nonlocal access for device management.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Review the CounterACT configuration to determine if an authentication server is required to access the device.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Directory.
3. Verify the selected authentication server is enabled for GUI authentication.

If an authentication server is not configured for use by CounterACT, this is a finding.'
  desc 'fix', 'Configure CounterACT to use an authentication server to access the device.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Directory.
3. Enable the selected authentication server.'
  impact 0.3
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75941r1_chk'
  tag severity: 'low'
  tag gid: 'V-76255'
  tag rid: 'SV-90943r1_rule'
  tag stig_id: 'CACT-NM-000086'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-82891r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end

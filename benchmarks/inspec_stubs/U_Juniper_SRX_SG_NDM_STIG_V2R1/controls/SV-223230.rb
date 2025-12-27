control 'SV-223230' do
  title 'The Juniper SRX Services Gateway must terminate the console session when the serial cable connected to the console port is unplugged.'
  desc 'If a device management session or connection remains open after management is completed, it may be hijacked by an attacker and used to compromise or damage the network device.'
  desc 'check', 'Verify this setting by entering the following commands in configuration mode.

[edit]
show system ports console

If the log-out-on-disconnect is not set for the console port, this is a finding.'
  desc 'fix', 'Configure this setting by entering the following commands in configuration mode.

[edit]
system ports console set log-out-on-disconnect'
  impact 0.3
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24903r513377_chk'
  tag severity: 'low'
  tag gid: 'V-223230'
  tag rid: 'SV-223230r513379_rule'
  tag stig_id: 'JUSX-DM-000154'
  tag gtitle: 'SRG-APP-000186-NDM-000266'
  tag fix_id: 'F-24891r513378_fix'
  tag 'documentable'
  tag legacy: ['SV-81091', 'V-66601']
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end

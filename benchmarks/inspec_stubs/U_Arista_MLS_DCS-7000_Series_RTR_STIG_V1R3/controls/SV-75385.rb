control 'SV-75385' do
  title 'The Arista Multilayer Switch must configure the maximum hop limit value to at least 32.'
  desc 'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message to be used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached their destination.'
  desc 'check', 'Review the router configuration to determine if the maximum hop limit has been configured.

If it has been configured, then it must be set to at least 32.

If it has not been configured, the default value must be determined. The default value for the Arista MLS is 64.

Review the interface configuration via the "show running-config" command for the statement

ipv6 nd ra hop-limit 32

If the default value is below 32 and the maximum hop limit value has not been configured (set to at least 32), this is a finding.

In any case, maximum hop limit must be at least 32.'
  desc 'fix', 'Configure the router maximum hop limit value to at least 32.

From the interface configuration mode, enter:

ipv6 nd ra hop-limit 32'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60927'
  tag rid: 'SV-75385r2_rule'
  tag stig_id: 'AMLS-L3-000290'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag fix_id: 'F-66639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

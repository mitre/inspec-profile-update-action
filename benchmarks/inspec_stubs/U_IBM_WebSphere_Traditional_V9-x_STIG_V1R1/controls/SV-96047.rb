control 'SV-96047' do
  title 'The WebSphere Application Server must authenticate all network-connected endpoint devices before establishing any connection.'
  desc '<0> [object Object]'
  desc 'check', 'Review System Security Plan documentation.

Identify mutual authentication connection requirements.

From the admin console, navigate to Security >> SSL Certificate and Key Management >> SSL Configuration.

Select each [NodeDefaultSSLSettings] then go to Quality of Protection (QoP) Settings.

If "Client authentication" is not set according to the security plan, this is a finding.'
  desc 'fix', 'From the admin console, navigate to Security >> SSL Certificate and Key Management >> SSL Configuration.

For each [NodeDefaultSSLSettings] select Quality of Protection (QoP) Settings.

Set "Client authentication" according to the security plan.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81037r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81333'
  tag rid: 'SV-96047r1_rule'
  tag stig_id: 'WBSP-AS-001110'
  tag gtitle: 'SRG-APP-000394-AS-000241'
  tag fix_id: 'F-88117r1_fix'
  tag cci: ['CCI-000187', 'CCI-001958']
  tag nist: ['IA-5 (2) (a) (2)', 'IA-3']
end

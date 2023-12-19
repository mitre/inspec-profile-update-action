control 'SV-96055' do
  title 'The WebSphere Application Server must authenticate all endpoint devices before establishing a local, remote, and/or network connection using bidirectional authentication that is cryptographically based.'
  desc '<0> [object Object]'
  desc 'check', 'Review System Security Plan documentation.

Identify mutual authentication connection requirements.

From the admin console, navigate to Security >> SSL Certificate and Key Management >> SSL Configuration.

Select each [NodeDefaultSSLSettings] then go to Quality of Protection (QoP) Settings.

If "Client authentication" is not set according to the security plan, this is a finding.

Note: with LDAP registry, the entire DN in the certificate is used to look up LDAP. Filters may be configured. With other registries, only the first attribute after the first "=", e.g., CN=<user> is used.'
  desc 'fix', 'From the admin console, navigate to Security >> SSL Certificate and Key Management >> SSL Configuration.

For each [NodeDefaultSSLSettings] select Quality of Protection (QoP) Settings.

Set "Client authentication" according to the security plan.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81047r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81341'
  tag rid: 'SV-96055r1_rule'
  tag stig_id: 'WBSP-AS-001120'
  tag gtitle: 'SRG-APP-000395-AS-000109'
  tag fix_id: 'F-88125r1_fix'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end

control 'SV-252634' do
  title 'The IBM Aspera High-Speed Transfer Server must enable the use of dynamic token encryption keys.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.
The dynamic token encryption key is used for encrypting authorization tokens dynamically for improved security and time-limited validity which limits the chances of a key becoming compromised.
NOTE: A dynamic token encryption key can be set for an individual user or a system group.

'
  desc 'check', 'Verify the Aspera High-Speed Transfer Server enables the use of dynamic token encryption keys with the following command:

$ sudo /opt/aspera/bin/asuserdata -a | grep dynamic

token_dynamic_key: "true"

If the "dynamic_key" setting is not set to "true", this is a finding.'
  desc 'fix', 'Configure the Aspera High-Speed Transfer Server to enable the use of dynamic token encryption keys with the following command:

$ sudo asconfigurator -x "set_node_data; token_dynamic_key,true"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56090r818070_chk'
  tag severity: 'medium'
  tag gid: 'V-252634'
  tag rid: 'SV-252634r818072_rule'
  tag stig_id: 'ASP4-TS-020180'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-56040r818071_fix'
  tag satisfies: ['SRG-NET-000062-ALG-000011', 'SRG-NET-000400-ALG-000097']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)']
end

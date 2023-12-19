control 'SV-258971' do
  title 'The vCenter STS service must be configured to use strong encryption ciphers.'
  desc '<0> [object Object]'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector/SSLHostConfig/@ciphers' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

ciphers="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

If each result returned does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

For each connector with "SSLEnabled" set to true, configure the ciphers attribute under the "SSLHostConfig" as follows:

ciphers="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Secure Token Service (STS)'
  tag check_id: 'C-62711r934569_chk'
  tag severity: 'medium'
  tag gid: 'V-258971'
  tag rid: 'SV-258971r934571_rule'
  tag stig_id: 'VCST-80-000002'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-62620r934570_fix'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-001453', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'AC-17 (2)', 'SC-8']
end

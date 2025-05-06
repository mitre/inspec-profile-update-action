control 'SV-235759' do
  title 'Edge must be configured to allow only TLS.'
  desc 'Sets the minimum supported version of SSL. If this policy is not configured, Microsoft Edge uses a default minimum version, TLS 1.0.

If this policy is enabled, the minimum version can be set to one of the following values: "TLSv1", "TLSv1.1" or "TLSv1.2". When set, Microsoft Edge will not use any version of SSL/TLS lower than the specified version. Any unrecognized value is ignored.

Policy options mapping:
- TLSv1 (tls1) = TLS 1.0
- TLSv1.1 (tls1.1) = TLS 1.1
- TLSv1.2 (tls1.2) = TLS 1.2

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Minimum TLS version enabled" must be set to "TLS 1.2".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for SSLVersionMin is not set to "REG_SZ = tls1.2", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Minimum TLS version enabled" to "TLS 1.2".'
  impact 0.7
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38978r626473_chk'
  tag severity: 'high'
  tag gid: 'V-235759'
  tag rid: 'SV-235759r626523_rule'
  tag stig_id: 'EDGE-00-000046'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-38941r626474_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end

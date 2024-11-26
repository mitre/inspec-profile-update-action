control 'SV-235761' do
  title 'Supported authentication schemes must be configured.'
  desc 'This setting specifies which HTTP authentication schemes are supported.

The policy can be configured by using these values: "basic", "digest", "ntlm", and "negotiate". Separate multiple values with commas.

If this policy is not configured, all four schemes are used.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/HTTP authentication/Supported authentication schemes" must be set to  "ntlm,negotiate".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "AuthSchemes" is not set to "REG_SZ = ntlm,negotiate", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/HTTP authentication/Supported authentication schemes" to "ntlm,negotiate".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38980r766864_chk'
  tag severity: 'medium'
  tag gid: 'V-235761'
  tag rid: 'SV-235761r766865_rule'
  tag stig_id: 'EDGE-00-000048'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-38943r626480_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

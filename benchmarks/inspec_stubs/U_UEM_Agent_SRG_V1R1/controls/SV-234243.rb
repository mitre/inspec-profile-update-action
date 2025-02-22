control 'SV-234243' do
  title 'The UEM Agent must only accept policies and policy updates that are digitally signed by a certificate that has been authorized for policy updates by the UEM Server.'
  desc 'It is critical that the UEM agent only use validated certificates for policy updates. Otherwise, there is no assurance that a malicious actor has not inserted itself in the process of packaging the code or policy.

'
  desc 'check', 'Verify the UEM Agent only accepts policies and policy updates that are digitally signed by a certificate that has been authorized for policy updates by the UEM Server.

If the UEM Agent does not only accept policies and policy updates that are digitally signed by a certificate that has been authorized for policy updates by the UEM Server, this is a finding.'
  desc 'fix', 'Configure the UEM Agent to only accept policies and policy updates that are digitally signed by a certificate that has been authorized for policy updates by the UEM Server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37428r612035_chk'
  tag severity: 'medium'
  tag gid: 'V-234243'
  tag rid: 'SV-234243r617354_rule'
  tag stig_id: 'SRG-APP-000427-UEM-100007'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-37393r612036_fix'
  tag satisfies: ['FMT_POL_EXT.2.1']
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

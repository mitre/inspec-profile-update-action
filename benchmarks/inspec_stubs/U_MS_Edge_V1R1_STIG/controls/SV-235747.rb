control 'SV-235747' do
  title 'Online revocation checks must be performed.'
  desc 'Control whether online revocation checks (OCSP/CRL checks) are required. If Microsoft Edge cannot get revocation status information, these certificates are treated as revoked ("hard-fail").

If this policy is enabled, Microsoft Edge always performs revocation checking for server certificates that successfully validate and are signed by locally installed CA certificates.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Specify if online OCSP/CRL checks are required for local trust anchors" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "RequireOnlineRevocationChecksForLocalAnchors" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Specify if online OCSP/CRL checks are required for local trust anchors" to "enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38966r626437_chk'
  tag severity: 'medium'
  tag gid: 'V-235747'
  tag rid: 'SV-235747r626523_rule'
  tag stig_id: 'EDGE-00-000030'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-38929r626438_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

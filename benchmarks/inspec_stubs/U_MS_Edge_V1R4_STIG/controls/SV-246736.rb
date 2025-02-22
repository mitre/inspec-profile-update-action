control 'SV-246736' do
  title 'Use of the QUIC protocol must be disabled.'
  desc "QUIC is used by more than half of all connections from the Edge web browser to Google's servers, and this activity is undesirable in the DoD.

If you enable this policy or don't configure it, the QUIC protocol is allowed.

If you disable this policy, the QUIC protocol is blocked."
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow QUIC protocol" must be set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "QuicAllowed" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Allow QUIC protocol" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-50168r766827_chk'
  tag severity: 'medium'
  tag gid: 'V-246736'
  tag rid: 'SV-246736r766829_rule'
  tag stig_id: 'EDGE-00-000063'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-50122r766828_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

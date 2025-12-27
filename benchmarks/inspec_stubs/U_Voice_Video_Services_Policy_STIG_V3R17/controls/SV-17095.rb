control 'SV-17095' do
  title 'Unified Capabilities (UC) soft clients must be tested and approved prior to implementation.'
  desc 'It is important that UC soft clients be tested and subsequently certified and accredited for IA purposes, to include upgrades or patches. Applications that have not been sufficiently vetted may introduce malware to the network or have security issues an adversary may manipulate.'
  desc 'check', 'Review the site documentation to confirm UC soft clients are tested and approved prior to implementation. If the confirm UC soft clients are not tested and approved prior to implementation, this is a finding.'
  desc 'fix', 'Ensure UC soft clients are tested and approved prior to implementation.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17151r3_chk'
  tag severity: 'medium'
  tag gid: 'V-16107'
  tag rid: 'SV-17095r2_rule'
  tag stig_id: 'VVoIP 1125'
  tag gtitle: 'VVoIP 1125'
  tag fix_id: 'F-16212r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end

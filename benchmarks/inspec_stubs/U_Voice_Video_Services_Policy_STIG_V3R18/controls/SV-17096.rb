control 'SV-17096' do
  title 'Unified Capabilities (UC) soft client patches and upgrades must be tested and approved prior to implementation.'
  desc 'It is important that UC soft clients be tested and subsequently certified and accredited for IA purposes, to include upgrades or patches. Applications that have not been sufficiently vetted may introduce malware to the network or have security issues an adversary may manipulate.'
  desc 'check', 'Review the site documentation to confirm the UC soft client patches and upgrades are tested and approved prior to implementation. If the UC soft client patches and upgrades are not tested and approved prior to implementation, this is a finding.'
  desc 'fix', 'Ensure UC soft client patches and upgrades are tested and approved prior to implementation.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16108'
  tag rid: 'SV-17096r2_rule'
  tag stig_id: 'VVoIP 1130'
  tag gtitle: 'VVoIP 1130'
  tag fix_id: 'F-16214r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end

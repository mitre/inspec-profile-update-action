control 'SV-233064' do
  title 'The container platform must be built from verified packages.'
  desc 'It is important to patch and upgrade the container platform when patches and upgrades are available. More important is to get these patches and upgrades from a known source. To validate the authenticity of any patches and upgrades before installation, the container platform must check that the files are digitally signed by sources approved by the organization.'
  desc 'check', 'Review the container platform configuration to verify it has been built from packages that are digitally signed by known and approved sources. 

If the container platform was built from packages that are not digitally signed or are from unknown or non-approved sources, this is a finding.'
  desc 'fix', 'Rebuild the container platform from verified packages that are digitally signed by known and approved sources.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36000r601694_chk'
  tag severity: 'medium'
  tag gid: 'V-233064'
  tag rid: 'SV-233064r879584_rule'
  tag stig_id: 'SRG-APP-000131-CTR-000280'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-35968r600680_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

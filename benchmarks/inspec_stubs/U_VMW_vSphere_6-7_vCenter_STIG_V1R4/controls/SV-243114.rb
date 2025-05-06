control 'SV-243114' do
  title 'The vCenter Server must enable certificate based authentication.'
  desc 'The vSphere Client is capable of CAC authentication. This capability must be enabled and properly configured.'
  desc 'check', 'See supplemental document.

Ensure that CAC authentication is required to log in to the vSphere Client. If CAC authentication is not required, this is a finding.'
  desc 'fix', 'Configure CAC Authentication per supplemental document.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46389r719583_chk'
  tag severity: 'medium'
  tag gid: 'V-243114'
  tag rid: 'SV-243114r879887_rule'
  tag stig_id: 'VCTR-67-000059'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46346r719584_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

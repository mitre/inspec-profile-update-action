control 'SV-216878' do
  title 'The vCenter Server for Windows must enable certificate based authentication.'
  desc 'The vCenter 6.5 Web Client portal is capable of CAC authentication. This capability must be enabled and properly configured.'
  desc 'check', 'See supplemental document.

Ensure CAC Authentication occurs upon login to vCenter.  Otherwise, this is a finding.'
  desc 'fix', 'Configure CAC Authentication per supplemental document.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18109r366348_chk'
  tag severity: 'medium'
  tag gid: 'V-216878'
  tag rid: 'SV-216878r879887_rule'
  tag stig_id: 'VCWN-65-000059'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18107r366349_fix'
  tag 'documentable'
  tag legacy: ['SV-104651', 'V-94821']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

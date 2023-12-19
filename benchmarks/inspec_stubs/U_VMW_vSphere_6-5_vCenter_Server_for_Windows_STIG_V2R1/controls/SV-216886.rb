control 'SV-216886' do
  title 'The vCenter Server for Windows must disable the Customer Experience Improvement Program (CEIP).'
  desc 'The VMware Customer Experience Improvement Program (CEIP) sends VMware anonymized system information that is used to improve the quality, reliability, and functionality of VMware products and services. For confidentiality purposes this feature must be disabled.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Deployment >> Customer Experience Improvement Program

If Customer Experience Improvement Program is Enabled, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Deployment >> Customer Experience Improvement Program

Click the "Leave" button'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18117r366372_chk'
  tag severity: 'low'
  tag gid: 'V-216886'
  tag rid: 'SV-216886r612237_rule'
  tag stig_id: 'VCWN-65-000067'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18115r366373_fix'
  tag 'documentable'
  tag legacy: ['V-94837', 'SV-104667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

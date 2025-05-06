control 'SV-243122' do
  title 'The vCenter Server must disable the Customer Experience Improvement Program (CEIP).'
  desc 'The VMware CEIP sends VMware anonymized system information that is used to improve the quality, reliability, and functionality of VMware products and services. For confidentiality purposes, this feature must be disabled.'
  desc 'check', 'From the vSphere Client, go to Administration >> Deployment >> Customer Experience Improvement Program.

If Customer Experience Improvement "Program Status" is "Joined", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Deployment >> Customer Experience Improvement Program.

Click the "Leave" button.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46397r719607_chk'
  tag severity: 'medium'
  tag gid: 'V-243122'
  tag rid: 'SV-243122r879887_rule'
  tag stig_id: 'VCTR-67-000067'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46354r719608_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

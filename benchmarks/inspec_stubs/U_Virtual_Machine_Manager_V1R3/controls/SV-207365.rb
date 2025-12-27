control 'SV-207365' do
  title 'The VMM must protect audit information from unauthorized deletion.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the VMM must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design. 

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit VMM activity.'
  desc 'check', 'Verify the VMM protects audit information from unauthorized deletion. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7622r365505_chk'
  tag severity: 'medium'
  tag gid: 'V-207365'
  tag rid: 'SV-207365r378655_rule'
  tag stig_id: 'SRG-OS-000059-VMM-000280'
  tag gtitle: 'SRG-OS-000059'
  tag fix_id: 'F-7622r365506_fix'
  tag 'documentable'
  tag legacy: ['V-56911', 'SV-71171']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end

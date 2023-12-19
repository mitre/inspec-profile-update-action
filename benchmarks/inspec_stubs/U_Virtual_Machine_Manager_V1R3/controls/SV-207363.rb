control 'SV-207363' do
  title 'The VMM must protect audit information from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult to achieve. To ensure the confidentiality of audit data, the VMM must protect audit information from unauthorized access.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit VMM activity.'
  desc 'check', 'Verify the VMM protects audit information from unauthorized read access. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7620r365499_chk'
  tag severity: 'medium'
  tag gid: 'V-207363'
  tag rid: 'SV-207363r378649_rule'
  tag stig_id: 'SRG-OS-000057-VMM-000260'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-7620r365500_fix'
  tag 'documentable'
  tag legacy: ['V-56905', 'SV-71165']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end

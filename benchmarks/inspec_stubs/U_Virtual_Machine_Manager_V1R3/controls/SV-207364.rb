control 'SV-207364' do
  title 'The VMM must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve. 

To ensure the veracity of audit data, the VMM must protect audit information from unauthorized modification. 

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit VMM activity.'
  desc 'check', 'Verify the VMM protects audit information from unauthorized modification. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7621r365502_chk'
  tag severity: 'medium'
  tag gid: 'V-207364'
  tag rid: 'SV-207364r378652_rule'
  tag stig_id: 'SRG-OS-000058-VMM-000270'
  tag gtitle: 'SRG-OS-000058'
  tag fix_id: 'F-7621r365503_fix'
  tag 'documentable'
  tag legacy: ['V-56907', 'SV-71167']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end

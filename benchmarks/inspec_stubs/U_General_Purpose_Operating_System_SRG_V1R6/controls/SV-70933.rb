control 'SV-70933' do
  title 'The operating system must protect audit information from unauthorized modification.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized modification.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Verify the operating system protects audit information from unauthorized modification. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit information from unauthorized modification.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56673'
  tag rid: 'SV-70933r1_rule'
  tag stig_id: 'SRG-OS-000058-GPOS-00028'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-61569r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end

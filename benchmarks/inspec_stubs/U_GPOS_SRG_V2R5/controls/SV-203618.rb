control 'SV-203618' do
  title 'The operating system must protect audit information from unauthorized deletion.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Verify the operating system protects audit information from unauthorized deletion. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3743r557578_chk'
  tag severity: 'medium'
  tag gid: 'V-203618'
  tag rid: 'SV-203618r557580_rule'
  tag stig_id: 'SRG-OS-000059-GPOS-00029'
  tag gtitle: 'SRG-OS-000059'
  tag fix_id: 'F-3743r557579_fix'
  tag 'documentable'
  tag legacy: ['SV-70935', 'V-56675']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end

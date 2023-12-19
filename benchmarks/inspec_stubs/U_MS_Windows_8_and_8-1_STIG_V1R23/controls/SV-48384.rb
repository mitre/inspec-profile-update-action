control 'SV-48384' do
  title 'The system must support automated patch management tools to facilitate flaw remediation to organization defined information system components.'
  desc 'The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.'
  desc 'check', 'Verify the organization has an automated process to install security-related software updates.  If it does not, this is a finding.'
  desc 'fix', 'Establish a process to automatically install security-related software updates.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36735'
  tag rid: 'SV-48384r2_rule'
  tag stig_id: 'WN08-GE-000029'
  tag gtitle: 'WINGE-000029'
  tag fix_id: 'F-41515r1_fix'
  tag 'documentable'
  tag ia_controls: 'VIVM-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

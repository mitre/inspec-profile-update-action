control 'SV-225435' do
  title 'The system must support automated patch management tools to facilitate flaw remediation.'
  desc 'The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes).  Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.'
  desc 'check', 'Verify the organization has an automated process to install security-related software updates.  If it does not, this is a finding.'
  desc 'fix', 'Establish a process to automatically install security-related software updates.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27134r471647_chk'
  tag severity: 'medium'
  tag gid: 'V-225435'
  tag rid: 'SV-225435r569185_rule'
  tag stig_id: 'WN12-GE-000024'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-27122r471648_fix'
  tag 'documentable'
  tag legacy: ['V-36735', 'SV-51583']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

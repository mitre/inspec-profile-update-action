control 'SV-203616' do
  title 'The operating system must protect audit information from unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify the operating system protects audit information from unauthorized read access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3741r557572_chk'
  tag severity: 'medium'
  tag gid: 'V-203616'
  tag rid: 'SV-203616r557574_rule'
  tag stig_id: 'SRG-OS-000057-GPOS-00027'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-3741r557573_fix'
  tag 'documentable'
  tag legacy: ['V-56671', 'SV-70931']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end

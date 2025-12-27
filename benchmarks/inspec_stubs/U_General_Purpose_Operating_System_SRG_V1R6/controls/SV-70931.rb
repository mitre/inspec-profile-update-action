control 'SV-70931' do
  title 'The operating system must protect audit information from unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.'
  desc 'check', 'Verify the operating system protects audit information from unauthorized read access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect audit information from unauthorized read access.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56671'
  tag rid: 'SV-70931r1_rule'
  tag stig_id: 'SRG-OS-000057-GPOS-00027'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-61567r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end

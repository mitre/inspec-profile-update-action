control 'SV-222644' do
  title 'Prior to each release of the application, updates to system, or applying patches; tests plans and procedures must be created and executed.'
  desc 'Without test plans and procedures for application releases or updates, unexpected results may occur which could lead to a denial of service to the application or components.

This requirement is meant to apply to developers or organizations that are doing development work when releasing a version update or a patch to the application.'
  desc 'check', 'If the review is not being done with the developer of the application, this requirement is not applicable.

Ask the application representative to provide tests plans, procedures, and results to ensure they are updated for each application release or updates to system patches.

If test plans, procedures, and results do not exist, or are not updated for each application release, this is a finding.'
  desc 'fix', 'Execute tests plans prior to release or patch update.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24314r493840_chk'
  tag severity: 'low'
  tag gid: 'V-222644'
  tag rid: 'SV-222644r508029_rule'
  tag stig_id: 'APSC-DV-003130'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24303r493841_fix'
  tag 'documentable'
  tag legacy: ['V-70367', 'SV-84989']
  tag cci: ['CCI-000366', 'CCI-003004']
  tag nist: ['CM-6 b', 'PM-14 a 2']
end

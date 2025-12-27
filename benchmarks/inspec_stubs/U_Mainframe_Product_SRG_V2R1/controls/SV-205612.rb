control 'SV-205612' do
  title 'The Mainframe Product must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies privileged functions, writes to SMF, and/or provides an SAF call to an external security manager (ESM) to generate audit records for all privilege activities or other system-level access. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call for privileged activities or other system-level access.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5878r300063_chk'
  tag severity: 'medium'
  tag gid: 'V-205612'
  tag rid: 'SV-205612r400846_rule'
  tag stig_id: 'SRG-APP-000504-MFP-000129'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-5878r300064_fix'
  tag 'documentable'
  tag legacy: ['SV-82709', 'V-68219']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

control 'SV-205610' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to delete categories of information (e.g., classification levels) occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security categories of information; writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to delete categories of information. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to delete categories of information occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5876r300057_chk'
  tag severity: 'medium'
  tag gid: 'V-205610'
  tag rid: 'SV-205610r400840_rule'
  tag stig_id: 'SRG-APP-000502-MFP-000127'
  tag gtitle: 'SRG-APP-000502'
  tag fix_id: 'F-5876r300058_fix'
  tag 'documentable'
  tag legacy: ['SV-82705', 'V-68215']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

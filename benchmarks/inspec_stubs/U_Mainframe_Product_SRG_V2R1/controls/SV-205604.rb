control 'SV-205604' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security object; writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to modify security objects. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to modify security objects occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5870r300039_chk'
  tag severity: 'medium'
  tag gid: 'V-205604'
  tag rid: 'SV-205604r400765_rule'
  tag stig_id: 'SRG-APP-000496-MFP-000121'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-5870r300040_fix'
  tag 'documentable'
  tag legacy: ['SV-82691', 'V-68201']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

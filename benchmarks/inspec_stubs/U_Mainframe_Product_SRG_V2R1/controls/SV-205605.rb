control 'SV-205605' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to modify security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security levels writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to modify security levels. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to modify security levels occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5871r300042_chk'
  tag severity: 'medium'
  tag gid: 'V-205605'
  tag rid: 'SV-205605r400825_rule'
  tag stig_id: 'SRG-APP-000497-MFP-000122'
  tag gtitle: 'SRG-APP-000497'
  tag fix_id: 'F-5871r300043_fix'
  tag 'documentable'
  tag legacy: ['SV-82695', 'V-68205']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

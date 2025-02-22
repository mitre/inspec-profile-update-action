control 'SV-205601' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to access security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security levels and writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to access security levels. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to access security levels.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5867r300030_chk'
  tag severity: 'medium'
  tag gid: 'V-205601'
  tag rid: 'SV-205601r400756_rule'
  tag stig_id: 'SRG-APP-000493-MFP-000118'
  tag gtitle: 'SRG-APP-000493'
  tag fix_id: 'F-5867r300031_fix'
  tag 'documentable'
  tag legacy: ['SV-82685', 'V-68195']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

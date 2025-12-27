control 'SV-82703' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to delete security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security object writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to delete security objects. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to delete security objects occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68213'
  tag rid: 'SV-82703r1_rule'
  tag stig_id: 'SRG-APP-000501-MFP-000126'
  tag gtitle: 'SRG-APP-000501-MFP-000126'
  tag fix_id: 'F-74327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

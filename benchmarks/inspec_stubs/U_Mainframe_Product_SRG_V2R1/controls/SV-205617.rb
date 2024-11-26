control 'SV-205617' do
  title 'The Mainframe Product must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product has no function or capability for account creations, this is not applicable.

Examine installation and configuration settings.

Verify that the Mainframe Product identifies account functions, writes to SMF, and/or uses an external security manager (ESM) to generate audit records for all account  creations, modifications, disabling, and termination events. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF call for all account creations, modifications, disabling, and termination events.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5883r300078_chk'
  tag severity: 'medium'
  tag gid: 'V-205617'
  tag rid: 'SV-205617r400861_rule'
  tag stig_id: 'SRG-APP-000509-MFP-000134'
  tag gtitle: 'SRG-APP-000509'
  tag fix_id: 'F-5883r300079_fix'
  tag 'documentable'
  tag legacy: ['SV-82719', 'V-68229']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

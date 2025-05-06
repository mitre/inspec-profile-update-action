control 'SV-82715' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies access to all objects; writes to SMF and/or and uses an external security manager to generate audit records for all access. If it does not, this is a finding'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF call when successful/unsuccessful accesses to objects occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68225'
  tag rid: 'SV-82715r1_rule'
  tag stig_id: 'SRG-APP-000507-MFP-000132'
  tag gtitle: 'SRG-APP-000507-MFP-000132'
  tag fix_id: 'F-74339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

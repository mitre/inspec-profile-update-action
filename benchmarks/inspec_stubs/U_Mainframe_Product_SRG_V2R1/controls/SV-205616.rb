control 'SV-205616' do
  title 'The Mainframe Product must generate audit records for all direct access to the information system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies direct access to the Mainframe Product, writes to SMF, and/or uses an external security manager (ESM) to generate audit records for all direct access. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF call for all direct access to the information system.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5882r300075_chk'
  tag severity: 'medium'
  tag gid: 'V-205616'
  tag rid: 'SV-205616r400858_rule'
  tag stig_id: 'SRG-APP-000508-MFP-000133'
  tag gtitle: 'SRG-APP-000508'
  tag fix_id: 'F-5882r300076_fix'
  tag 'documentable'
  tag legacy: ['SV-82717', 'V-68227']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

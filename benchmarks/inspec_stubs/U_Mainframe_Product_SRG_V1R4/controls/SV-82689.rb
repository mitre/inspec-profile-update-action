control 'SV-82689' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies all security privileges, writes to SMF, and/or uses an external security manager (ESM) to generate audit records successful/unsuccessful attempts to modify privileges occur. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to modify privileges occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68199'
  tag rid: 'SV-82689r1_rule'
  tag stig_id: 'SRG-APP-000495-MFP-000120'
  tag gtitle: 'SRG-APP-000495-MFP-000120'
  tag fix_id: 'F-74315r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

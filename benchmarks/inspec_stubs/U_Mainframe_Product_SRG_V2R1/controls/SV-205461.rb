control 'SV-205461' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine the installation and configuration settings.

Verify that the Mainframe Product identifies privileged functions and writes to SMF and/or uses an external security manager to generate audit records when successful/unsuccessful attempts to access privileges occur. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF call for the external security manager when successful/unsuccessful attempts to access privileges occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5727r299616_chk'
  tag severity: 'medium'
  tag gid: 'V-205461'
  tag rid: 'SV-205461r395712_rule'
  tag stig_id: 'SRG-APP-000091-MFP-000116'
  tag gtitle: 'SRG-APP-000091'
  tag fix_id: 'F-5727r299617_fix'
  tag 'documentable'
  tag legacy: ['SV-82681', 'V-68191']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

control 'SV-205607' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Examine installation and configuration settings.

Verify that the Mainframe Product identifies privileged functions, writes to SMF, and/or uses an external security manager (ESM) to generate audit records when successful/unsuccessful attempts to delete privileges occur. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to write to SMF and/or provide audit SAF to call when successful/unsuccessful attempts to delete privileges occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5873r300048_chk'
  tag severity: 'medium'
  tag gid: 'V-205607'
  tag rid: 'SV-205607r400831_rule'
  tag stig_id: 'SRG-APP-000499-MFP-000124'
  tag gtitle: 'SRG-APP-000499'
  tag fix_id: 'F-5873r300049_fix'
  tag 'documentable'
  tag legacy: ['SV-82699', 'V-68209']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

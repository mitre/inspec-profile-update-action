control 'SV-82707' do
  title 'The Mainframe Product must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product does not have the function or capability for user logon, this is not applicable.

Examine configuration settings.

Determine if successful/unsuccessful logon attempts are audited. If they are not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide audit SAF to call when successful/unsuccessful logon attempts occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68217'
  tag rid: 'SV-82707r1_rule'
  tag stig_id: 'SRG-APP-000503-MFP-000128'
  tag gtitle: 'SRG-APP-000503-MFP-000128'
  tag fix_id: 'F-74331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

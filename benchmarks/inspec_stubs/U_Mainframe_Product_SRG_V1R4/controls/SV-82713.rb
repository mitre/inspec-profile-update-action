control 'SV-82713' do
  title 'The Mainframe Product must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

Examine configuration settings.

If the Mainframe Product does not generate audit records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide audit SAF call when concurrent logons from different workstations occur.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68223'
  tag rid: 'SV-82713r1_rule'
  tag stig_id: 'SRG-APP-000506-MFP-000131'
  tag gtitle: 'SRG-APP-000506-MFP-000131'
  tag fix_id: 'F-74337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

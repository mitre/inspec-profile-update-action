control 'SV-205614' do
  title 'The Mainframe Product must generate audit records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

Examine configuration settings.

If the Mainframe Product does not generate audit records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide audit SAF call when concurrent logons from different workstations occur.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5880r300069_chk'
  tag severity: 'medium'
  tag gid: 'V-205614'
  tag rid: 'SV-205614r400852_rule'
  tag stig_id: 'SRG-APP-000506-MFP-000131'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-5880r300070_fix'
  tag 'documentable'
  tag legacy: ['SV-82713', 'V-68223']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

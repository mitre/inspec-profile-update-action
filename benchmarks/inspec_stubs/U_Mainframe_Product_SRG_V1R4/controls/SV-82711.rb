control 'SV-82711' do
  title 'The Mainframe Product must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product has no function or capability for user access this is not applicable.

Examine configuration settings. 

If the Mainframe Product does not identify and audit start and end times of access to the systems, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide audit SAF call for starting and ending time for user access to the system.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68221'
  tag rid: 'SV-82711r1_rule'
  tag stig_id: 'SRG-APP-000505-MFP-000130'
  tag gtitle: 'SRG-APP-000505-MFP-000130'
  tag fix_id: 'F-74335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

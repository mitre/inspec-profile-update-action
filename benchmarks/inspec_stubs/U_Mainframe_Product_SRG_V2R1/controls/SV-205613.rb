control 'SV-205613' do
  title 'The Mainframe Product must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'If the Mainframe Product has no function or capability for user access this is not applicable.

Examine configuration settings. 

If the Mainframe Product does not identify and audit start and end times of access to the systems, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide audit SAF call for starting and ending time for user access to the system.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5879r300066_chk'
  tag severity: 'medium'
  tag gid: 'V-205613'
  tag rid: 'SV-205613r400849_rule'
  tag stig_id: 'SRG-APP-000505-MFP-000130'
  tag gtitle: 'SRG-APP-000505'
  tag fix_id: 'F-5879r300067_fix'
  tag 'documentable'
  tag legacy: ['SV-82711', 'V-68221']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

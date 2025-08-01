control 'SRG-NET-000505-VVEP-00010_rule' do
  title 'The Unified Communications Endpoint must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing audit records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing audit records provide supplemental confirmation of monitored events. Unified Communications Endpoints that communicate beyond these defined environments must generate audit records.'
  desc 'check', 'Verify the Unified Communications Endpoint generates audit records showing starting and ending time for user access to the system.

If the Unified Communications Endpoint does not generate audit records showing starting and ending time for user access, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to generate audit records showing starting and ending time for user access to the system.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000505-VVEP-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000505-VVEP-00010'
  tag rid: 'SRG-NET-000505-VVEP-00010_rule'
  tag stig_id: 'SRG-NET-000505-VVEP-00010'
  tag gtitle: 'SRG-NET-000505-VVEP-00010'
  tag fix_id: 'F-SRG-NET-000505-VVEP-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

control 'SRG-NET-000334-VVEP-00010_rule' do
  title 'The Unified Communications Endpoint must offload audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity. 

Audit records are commonly produced by session management and border elements. Many Unified Communications Endpoints are not capable of providing audit records and instead rely on session management and border elements. Unified Communications Endpoints capable of producing audit records provide supplemental confirmation of monitored events. Unified Communications Endpoints that support audit records must support offloading.'
  desc 'check', 'Verify the Unified Communications Endpoint offloads audit records onto a different system or media.

If the Unified Communications Endpoint does not offload audit records to a different system or media, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to offload audit records to a different system or media.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000334-VVEP-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000334-VVEP-00010'
  tag rid: 'SRG-NET-000334-VVEP-00010_rule'
  tag stig_id: 'SRG-NET-000334-VVEP-00010'
  tag gtitle: 'SRG-NET-000334-VVEP-00010'
  tag fix_id: 'F-SRG-NET-000334-VVEP-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

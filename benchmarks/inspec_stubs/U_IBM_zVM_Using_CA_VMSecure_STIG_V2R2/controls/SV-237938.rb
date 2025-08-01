control 'SV-237938' do
  title 'CA VM:Secure product audit records must offload audit records to a different system or media.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'If there is no documented process for audit offload, this is a finding.

Examine the documented user process for audit record offload.

If the procedure does not offload to a different system or media, this is a finding.'
  desc 'fix', 'Develop a user written procedure to offload audit records to a different system or media.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41148r649652_chk'
  tag severity: 'medium'
  tag gid: 'V-237938'
  tag rid: 'SV-237938r851946_rule'
  tag stig_id: 'IBMZ-VM-000940'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-41107r649653_fix'
  tag 'documentable'
  tag legacy: ['SV-93629', 'V-78923']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

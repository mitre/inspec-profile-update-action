control 'SV-223805' do
  title 'IBM z/OS system administrator must develop a procedure to offload SMF files to a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Ask the system administrator for the procedure to offload SMF files to a different system or media than the system being audited.

If the procedure does not exist, this is a finding.'
  desc 'fix', 'Develop a procedure to offload SMF files to a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25478r515103_chk'
  tag severity: 'medium'
  tag gid: 'V-223805'
  tag rid: 'SV-223805r853630_rule'
  tag stig_id: 'RACF-OS-000510'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-25466r515104_fix'
  tag 'documentable'
  tag legacy: ['V-98317', 'SV-107421']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

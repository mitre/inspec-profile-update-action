control 'SV-223585' do
  title 'IBM z/OS system administrator must develop a procedure to offload SMF files to a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Ask the system administrator for the procedure to offload SMF files to a different system or media than the system being audited.

If the procedure does not exist, this is a finding.'
  desc 'fix', 'Develop a procedure to offload SMF files to a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25258r500890_chk'
  tag severity: 'medium'
  tag gid: 'V-223585'
  tag rid: 'SV-223585r533198_rule'
  tag stig_id: 'ACF2-OS-003430'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-25246r500891_fix'
  tag 'documentable'
  tag legacy: ['SV-106979', 'V-97875']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

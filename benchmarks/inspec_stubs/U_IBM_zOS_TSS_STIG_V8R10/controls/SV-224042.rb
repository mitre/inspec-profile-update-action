control 'SV-224042' do
  title 'IBM z/OS system administrator must develop a procedure to offload SMF files to a different system or media than the system being audited.'
  desc 'The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', 'Ask the system administrator for the procedure to offload SMF files to a different system or media than the system being audited.

If the procedure does not exist, this is a finding.'
  desc 'fix', 'Develop a procedure to offload SMF files to a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25715r516525_chk'
  tag severity: 'medium'
  tag gid: 'V-224042'
  tag rid: 'SV-224042r877880_rule'
  tag stig_id: 'TSS0-OS-000470'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-25703r516526_fix'
  tag 'documentable'
  tag legacy: ['SV-107895', 'V-98791']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

control 'SV-756' do
  title 'The system must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.'
  desc 'check', 'Check if the system requires a password when booted into single user mode. If it does not, this is a finding.'
  desc 'fix', 'Configure the system to require a password upon booting into single user mode.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27961r1_chk'
  tag severity: 'medium'
  tag gid: 'V-756'
  tag rid: 'SV-756r2_rule'
  tag stig_id: 'GEN000020'
  tag gtitle: 'GEN000020'
  tag fix_id: 'F-24306r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

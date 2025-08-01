control 'SV-203609' do
  title 'The operating system must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify the operating system generates audit records containing the full-text recording of privileged commands. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records containing the full-text recording of privileged commands.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3734r557083_chk'
  tag severity: 'medium'
  tag gid: 'V-203609'
  tag rid: 'SV-203609r557085_rule'
  tag stig_id: 'SRG-OS-000042-GPOS-00020'
  tag gtitle: 'SRG-OS-000042'
  tag fix_id: 'F-3734r557084_fix'
  tag 'documentable'
  tag legacy: ['V-56657', 'SV-70917']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end

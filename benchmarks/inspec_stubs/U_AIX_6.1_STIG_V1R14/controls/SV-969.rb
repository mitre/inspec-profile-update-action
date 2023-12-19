control 'SV-969' do
  title 'AIX Trusted Computing Base (TCB) software must be implemented.'
  desc 'The AIX Trusted Computing Base (TCB) software provides protection from the unauthorized modification of core system files.'
  desc 'check', 'Perform:

	# /bin/tcbck

If TCB is not installed, the output will show an error code of 3001-101 and/or a text message indicating TCB is not installed, this is a finding.'
  desc 'fix', 'Ensure the Trusted Computing Base (TCB) software is implemented.  TCB can only be installed at OS installation time.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-2321r2_chk'
  tag severity: 'medium'
  tag gid: 'V-969'
  tag rid: 'SV-969r2_rule'
  tag stig_id: 'GEN000000-AIX00020'
  tag gtitle: 'GEN000000-AIX00020'
  tag fix_id: 'F-31368r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000032', 'CCI-000633']
  tag nist: ['AC-4 (8) (a)', 'SA-4 (6) (b)']
end

control 'SV-12534' do
  title 'The root account must be the only account with GID of 0.'
  desc 'Accounts with a GID of 0 have root group privileges.'
  desc 'fix', 'Change the default GID of non-root accounts to a valid GID other than 0.'
  impact 0.7
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'high'
  tag gid: 'V-12033'
  tag rid: 'SV-12534r2_rule'
  tag stig_id: 'GEN000000-SOL00440'
  tag gtitle: 'GEN000000-SOL00440'
  tag fix_id: 'F-11290r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000225', 'CCI-000764']
  tag nist: ['AC-6', 'IA-2']
end

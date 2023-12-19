control 'SV-957' do
  title 'The /usr/aset/userlist file must have mode 0600 or less permissive.'
  desc 'A permission mask not set to the required level could allow unauthorized access to sensitive system files and resources.'
  desc 'fix', 'Change the mode of the /usr/aset/userlist file to 0600.
# chmod 0600 /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-957'
  tag rid: 'SV-957r2_rule'
  tag stig_id: 'GEN000000-SOL00260'
  tag gtitle: 'GEN000000-SOL00260'
  tag fix_id: 'F-1111r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-37436' do
  title 'There must be no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in .netrc files. Policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'fix', 'Remove the .netrc file(s).

Procedure:
# find / -name .netrc
# rm <.netrc file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-913'
  tag rid: 'SV-37436r1_rule'
  tag stig_id: 'GEN002000'
  tag gtitle: 'GEN002000'
  tag fix_id: 'F-31295r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

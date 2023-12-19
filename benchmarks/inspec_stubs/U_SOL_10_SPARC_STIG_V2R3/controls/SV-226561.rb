control 'SV-226561' do
  title 'There must be no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in .netrc files.  Policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'check', 'Check the system for the existence of any .netrc files.

Procedure:
# find / -name .netrc  

If any .netrc file exists, this is a finding.'
  desc 'fix', 'Remove the .netrc file(s).

Procedure:
# rm .netrc'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28722r483092_chk'
  tag severity: 'medium'
  tag gid: 'V-226561'
  tag rid: 'SV-226561r603265_rule'
  tag stig_id: 'GEN002000'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-28710r483093_fix'
  tag 'documentable'
  tag legacy: ['V-913', 'SV-913']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

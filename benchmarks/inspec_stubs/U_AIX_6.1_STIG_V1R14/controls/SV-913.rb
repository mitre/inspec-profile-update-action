control 'SV-913' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-404r2_chk'
  tag severity: 'medium'
  tag gid: 'V-913'
  tag rid: 'SV-913r2_rule'
  tag stig_id: 'GEN002000'
  tag gtitle: 'GEN002000'
  tag fix_id: 'F-1067r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

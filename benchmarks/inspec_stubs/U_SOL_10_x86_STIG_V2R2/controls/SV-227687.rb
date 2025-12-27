control 'SV-227687' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29849r488642_chk'
  tag severity: 'medium'
  tag gid: 'V-227687'
  tag rid: 'SV-227687r603266_rule'
  tag stig_id: 'GEN002000'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-29837r488643_fix'
  tag 'documentable'
  tag legacy: ['V-913', 'SV-913']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

control 'SV-215403' do
  title 'The AIX system must have no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in .netrc files. Policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'check', 'Check the system for the existence of any ".netrc" files by running the following command: 
# find / -name .netrc 

If any ".netrc" file exists, this is a finding.'
  desc 'fix', 'Remove all ".netrc" file(s):
#  find / -name .netrc -exec  rm {} \\;'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16601r294660_chk'
  tag severity: 'high'
  tag gid: 'V-215403'
  tag rid: 'SV-215403r508663_rule'
  tag stig_id: 'AIX7-00-003101'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-16599r294661_fix'
  tag 'documentable'
  tag legacy: ['V-91289', 'SV-101387']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

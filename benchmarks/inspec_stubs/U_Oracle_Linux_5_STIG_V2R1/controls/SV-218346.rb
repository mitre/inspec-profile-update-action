control 'SV-218346' do
  title 'There must be no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in .netrc files. Policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'check', 'Check the system for the existence of any .netrc files.

Procedure:
# find / -name .netrc

If any .netrc file exists, this is a finding.'
  desc 'fix', 'Remove the .netrc file(s).

Procedure:
# find / -name .netrc
# rm <.netrc file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19821r554375_chk'
  tag severity: 'medium'
  tag gid: 'V-218346'
  tag rid: 'SV-218346r603259_rule'
  tag stig_id: 'GEN002000'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-19819r554376_fix'
  tag 'documentable'
  tag legacy: ['V-913', 'SV-63591']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

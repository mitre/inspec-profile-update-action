control 'SV-227702' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', 'Check the permissions of audio devices.
# ls -lL /dev/audio
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /dev/audio'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29864r488687_chk'
  tag severity: 'medium'
  tag gid: 'V-227702'
  tag rid: 'SV-227702r603266_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29852r488688_fix'
  tag 'documentable'
  tag legacy: ['V-22367', 'SV-26496']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

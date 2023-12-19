control 'SV-226547' do
  title 'Skeleton files must not have extended ACLs.'
  desc "If the skeleton files are not protected, unauthorized personnel could change user's startup parameters and possibly jeopardize user's files."
  desc 'check', 'Check skeleton files for extended ACLs.
# ls -alL /etc/skel
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [skeleton file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28708r483047_chk'
  tag severity: 'medium'
  tag gid: 'V-226547'
  tag rid: 'SV-226547r603265_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28696r483048_fix'
  tag 'documentable'
  tag legacy: ['V-22357', 'SV-26475']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

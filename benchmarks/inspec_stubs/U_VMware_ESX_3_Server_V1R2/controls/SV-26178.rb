control 'SV-26178' do
  title 'The /etc/news/hosts.nntp.nolimit file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Excessive permissions on the hosts.nntp.nolimit file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/news/hosts.nntp.nolimit
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/news/hosts.nntp.nolimit file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22503'
  tag rid: 'SV-26178r1_rule'
  tag stig_id: 'GEN006290'
  tag gtitle: 'GEN006290'
  tag fix_id: 'F-26309r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

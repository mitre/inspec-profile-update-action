control 'SV-44988' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', "Verify /etc/nsswitch.conf has no extended ACL.
# ls -l /etc/nsswitch.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42395r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22330'
  tag rid: 'SV-44988r1_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'GEN001374'
  tag fix_id: 'F-38405r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

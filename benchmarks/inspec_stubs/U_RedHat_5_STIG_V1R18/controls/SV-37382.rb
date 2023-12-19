control 'SV-37382' do
  title 'The cron.allow file must not have an extended ACL.'
  desc 'A readable and/or writeable cron.allow file by other users than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', "Check the permissions of the cron.allow file.
# ls -l /etc/cron.allow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22384'
  tag rid: 'SV-37382r1_rule'
  tag stig_id: 'GEN002990'
  tag gtitle: 'GEN002990'
  tag fix_id: 'F-31313r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

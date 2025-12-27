control 'SV-26034' do
  title 'The cron.allow file must not have an extended ACL.'
  desc 'A cron.allow file that is readable and/or writable by other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check the permissions of the cron.allow file.
# ls -l /etc/cron.allow
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cron.allow file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22384'
  tag rid: 'SV-26034r1_rule'
  tag stig_id: 'GEN002990'
  tag gtitle: 'GEN002990'
  tag fix_id: 'F-26234r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

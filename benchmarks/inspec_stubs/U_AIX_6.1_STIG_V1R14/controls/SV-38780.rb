control 'SV-38780' do
  title 'The cron.allow file must not have an extended ACL.'
  desc 'A cron.allow file that is readable and/or writable by other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check the permissions of the cron.allow file.

#aclget /var/adm/cron/cron.allow
Verify if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cron.allow file and disable extended permissions.

#acledit /var/adm/cron/cron.allow'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22384'
  tag rid: 'SV-38780r1_rule'
  tag stig_id: 'GEN002990'
  tag gtitle: 'GEN002990'
  tag fix_id: 'F-32472r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

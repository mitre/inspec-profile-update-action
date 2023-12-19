control 'SV-227740' do
  title 'The cron.allow file must not have an extended ACL.'
  desc 'A cron.allow file that is readable and/or writable by other than root could allow potential intruders and malicious users to use the file contents to help discern information, such as who is allowed to execute cron programs, which could be harmful to overall system and network security.'
  desc 'check', 'Check the permissions of the cron.allow file.
# ls -l /etc/cron.allow
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29902r488804_chk'
  tag severity: 'medium'
  tag gid: 'V-227740'
  tag rid: 'SV-227740r603266_rule'
  tag stig_id: 'GEN002990'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29890r488805_fix'
  tag 'documentable'
  tag legacy: ['V-22384', 'SV-26528']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-26111' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', 'Examine /etc/syslog.conf and determine the log file(s) receiving logs for mail.crit, mail.debug, mail.*, or *.crit.
Check the permissions on these log files.
# ls -lL [log file]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the SMTP service log file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27710r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22442'
  tag rid: 'SV-26111r1_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'GEN004510'
  tag fix_id: 'F-26289r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

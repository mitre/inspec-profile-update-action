control 'SV-41546' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'fix', 'Edit the syslog.conf file and add a configuration line specifying an appropriate destination for mail.crit syslogs.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-41546r1_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-990r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3, ECSC-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

control 'SV-45976' do
  title 'The /etc/rsyslog.conf file must be owned by root.'
  desc 'If the /etc/syslog.conf file is not owned by root, unauthorized users could be allowed to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/rsyslog.conf ownership:

# ls –lL /etc/rsyslog* 

If any rsyslog configuration file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to set the owner to root.
# chown root <rsyslog configuration file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43258r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4393'
  tag rid: 'SV-45976r1_rule'
  tag stig_id: 'GEN005400'
  tag gtitle: 'GEN005400'
  tag fix_id: 'F-39341r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

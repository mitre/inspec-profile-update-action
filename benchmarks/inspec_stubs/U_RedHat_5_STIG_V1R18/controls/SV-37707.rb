control 'SV-37707' do
  title 'The /etc/syslog.conf file must be owned by root.'
  desc 'If the /etc/syslog.conf file is not owned by root, unauthorized users could be allowed to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'check', 'Check /etc/syslog.conf or /etc/rsyslog.conf ownership:

For syslog:
# ls -lL /etc/syslog.conf

For rsyslog:
# ls -lL /etc/rsyslog.conf

If /etc/syslog.conf or /etc/rsyslog.conf is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to set the owner to root.
# chown root /etc/syslog.conf   
Or:
# chown root /etc/rsyslog.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36904r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4393'
  tag rid: 'SV-37707r2_rule'
  tag stig_id: 'GEN005400'
  tag gtitle: 'GEN005400'
  tag fix_id: 'F-32061r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

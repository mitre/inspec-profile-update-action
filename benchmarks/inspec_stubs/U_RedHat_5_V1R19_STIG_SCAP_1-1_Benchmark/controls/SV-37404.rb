control 'SV-37404' do
  title 'The system must log informational authentication data.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.'
  desc 'fix', 'Edit /etc/syslog.conf or /etc/rsyslog.conf and add local log destinations for "authpriv.*", "authpriv.debug" or "authpriv.info".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12004'
  tag rid: 'SV-37404r2_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'GEN003660'
  tag fix_id: 'F-31333r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

control 'SV-37439' do
  title 'Inetd or xinetd logging/tracing must be enabled.'
  desc 'Inetd or xinetd logging and tracing allows the system administrators to observe the IP addresses connecting to their machines and what network services are being sought.  This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'fix', "Edit each file in the /etc/xinetd.d directory and the /etc/xinetd.conf file to contain:
log_type = SYSLOG authpriv
log_on_success = HOST PID USERID EXIT
log_on_failure = HOST USERID

The /etc/xinetd.conf file contains default values that will hold true for all services unless individually modified in the service's xinetd.d file.

To make the new settings effective, restart the xinetd service:
# service xinetd restart"
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-1011'
  tag rid: 'SV-37439r1_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'GEN003800'
  tag fix_id: 'F-31357r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

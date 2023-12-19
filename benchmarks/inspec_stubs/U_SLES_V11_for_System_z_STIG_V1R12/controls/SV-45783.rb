control 'SV-45783' do
  title 'Inetd or xinetd logging/tracing must be enabled.'
  desc 'Inetd or xinetd logging and tracing allows the system administrators to observe the IP addresses connecting to their machines and what network services are being sought.  This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'check', 'The /etc/xinetd.conf file and each file in the /etc/xinetd.d directory file should be examined for the following: 

Procedure:
log_type = SYSLOG authpriv
log_on_success = HOST PID USERID EXIT
log_on_failure = HOST USERID

If xinetd is running and logging is not enabled, this is a finding.'
  desc 'fix', "Edit each file in the /etc/xinetd.d directory and the /etc/xinetd.conf file to contain:
log_type = SYSLOG authpriv
log_on_success = HOST PID USERID EXIT
log_on_failure = HOST USERID

The /etc/xinetd.conf file contains default values that will hold true for all services unless individually modified in the service's xinetd.d file."
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43121r1_chk'
  tag severity: 'low'
  tag gid: 'V-1011'
  tag rid: 'SV-45783r1_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'GEN003800'
  tag fix_id: 'F-39178r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

control 'SV-218509' do
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

The /etc/xinetd.conf file contains default values that will hold true for all services unless individually modified in the service's xinetd.d file.

To make the new settings effective, restart the xinetd service:
# service xinetd restart"
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19984r562660_chk'
  tag severity: 'low'
  tag gid: 'V-218509'
  tag rid: 'SV-218509r603259_rule'
  tag stig_id: 'GEN003800'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-19982r562661_fix'
  tag 'documentable'
  tag legacy: ['V-1011', 'SV-63989']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

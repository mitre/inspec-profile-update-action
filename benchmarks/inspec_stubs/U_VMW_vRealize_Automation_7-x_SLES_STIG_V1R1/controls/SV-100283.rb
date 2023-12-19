control 'SV-100283' do
  title 'Xinetd logging/tracing must be enabled.'
  desc 'Xinetd logging and tracing allows the system administrators to observe the IP addresses that are connecting to their machines and to observe what network services are being sought. This provides valuable information when trying to find the source of malicious users and potential malicious users.'
  desc 'check', 'Examine the /etc/xinetd.conf file and each file in the /etc/xinetd.d directory file for the following:

log_type = SYSLOG authpriv
log_on_success = HOST PID USERID EXIT
log_on_failure = HOST USERID

If "xinetd" running and logging is not enabled, this is a finding.'
  desc 'fix', %q(Edit each file in the /etc/xinetd.d directory and the /etc/xinetd.conf file to contain:

log_type = SYSLOG authpriv
log_on_success = HOST PID USERID EXIT
log_on_failure = HOST USERID

The /etc/xinetd.conf file contains default values that will hold true for all services unless individually modified in the service's "xinetd.d" file.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89325r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89633'
  tag rid: 'SV-100283r1_rule'
  tag stig_id: 'VRAU-SL-000535'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96375r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

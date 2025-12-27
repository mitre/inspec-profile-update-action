control 'SV-38297' do
  title 'The system must use at least two time sources for clock synchronization.'
  desc "A synchronized system clock is critical for the enforcement of time-based policies and the correlation of logs and audit records with other systems. For redundancy, two time sources are required so synchronization continues to function if one source fails. 

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events or operation of time-dependent protocols between systems will be necessary. If the system is completely isolated, this requirement is not applicable.

NOTE: For the Network Time Protocol (NTP), the requirement is two servers, but it is recommended to configure at least four distinct time servers which allow NTP to effectively exclude a time source that is not consistent with the others. The system's local clock must be excluded from the count of time sources."
  desc 'check', 'Check the system for a running NTP daemon.
# ps -ef | grep ntp

Verify the auto-startup of (x)ntpd in /etc/rc.config.d/netdaemons.
# cat /etc/rc.config.d/netdaemons | grep -v "^#" | grep -i "XNTPD=1"

Verify at least two external NTP servers are listed in the /etc/ntp.conf file.
# cat /etc/ntp.conf | grep -v "^#" | grep -i server | \\
egrep -v "127.127.1.1|127.127.1.0"

If xntpd is not invoked with at least two external NTP servers listed (127.127.1.0 or 127.127.1.1 are local clock references and therefore not allowed), this is a finding.'
  desc 'fix', 'If auto-starting (x)ntpd, add (when necessary) the correct number of (at least two) external servers to the /etc/ntp.conf file.

If using ntpdate, add additional NTP servers (at least two are required) to the cron job running ntpdate.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22291'
  tag rid: 'SV-38297r1_rule'
  tag stig_id: 'GEN000242'
  tag gtitle: 'GEN000242'
  tag fix_id: 'F-31494r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000160']
  tag nist: ['AU-8 (1)']
end

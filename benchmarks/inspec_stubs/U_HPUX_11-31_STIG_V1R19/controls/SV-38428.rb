control 'SV-38428' do
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc 'To assure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD. Many system functions, including time-based login and activity restrictions, automated reports, system logs, and audit records depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

Authoritative time sources include authorized time servers within the enclave synchronized with upstream authoritative sources. Specific requirements for the upstream synchronization of Network Time Protocol (NTP) servers are covered in the Network Other Devices STIG.

For systems located on isolated or closed networks, it is not necessary to synchronize with a global authoritative time source. If a global authoritative time source is not available to systems on an isolated network, a local authoritative time source must be established on this network and used by the systems connected to this network. This is necessary to provide the ability to correlate events and allow for the correct operation of time-dependent protocols between systems on the isolated network.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'Check Content:  
Check the root crontab for ntpdate jobs running at least daily. If cron is used, this command must return a line with the following required format: columns 3, 4, and 5 must be an asterisk (*) for the job to be run daily.
# crontab -l | grep ntpdate

OR

Check that ntpd is used for system clock synchronization. If ntpd is used, this command must return a line starting with an asterisk followed by the name of the remote host that the local system is synchronized with.
# ntpq -p | grep "^*"

If the system clock is not being synchronized continuously (via ntpd) or at least daily (via cron), this is a finding.'
  desc 'fix', 'Use a local authoritative time server synchronizing to an authorized DoD time source. Ensure all systems in the facility feed from one or more local time servers feeding from the authoritative time server. 

View the current system (x)ntpd man page for a detailed discussion of configuration option details:
# man xntpd

Create/edit the ntp.conf file, delete any non-local and/or non-U.S. DoD sources and insert the local or an authoritative U.S. DoD source.

Example /etc/ntp.conf file:
#
# server : ntp server used (poll) to obtain time
server <IP or hostname for 1st server>
server <IP or hostname for 2nd server>
#
# peer : a peer relationship with another ntp server
peer <IP or hostname for ntp peer>
#
# driftfile : track local clock time (drift of the local clock)
driftfile <drift file name, default is /etc/ntp.drift>

Stop/restart (x)ntpd. The default system script to start ntp should be found in the system startup directory /sbin/init.d :
# /sbin/init.d/xntpd start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36233r4_chk'
  tag severity: 'medium'
  tag gid: 'V-4301'
  tag rid: 'SV-38428r1_rule'
  tag stig_id: 'GEN000240'
  tag gtitle: 'GEN000240'
  tag fix_id: 'F-31492r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001492']
  tag nist: ['AU-8 (1) (a)']
end

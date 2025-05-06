control 'SV-215208' do
  title 'AIX must provide time synchronization applications that can synchronize the system clock to external time sources at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Check if time synchronization application "ntpd" is running using the command:

# lssrc -s xntpd
Subsystem         Group            PID                  Status 
 xntpd                   tcpip          4784536             active

If "ntpd" is showing "inoperative", this is a finding.

Check that "ntp" server is configured using command: 

# grep server /etc/ntp.conf
server 10.110.20.10

If the command returns no output, this is a finding.

Check the poll interval is less than 24 hours using command:

# grep maxpoll /etc/ntp.conf
maxpoll=16

If "maxpoll" is set to larger than "16" (2^16 seconds ~= 18hr), this is a finding.'
  desc 'fix', 'Edit /etc/ntp.conf

Configure ntp server by adding the following line:
server server_ipaddr

Set maxpoll to <value>   <=16 by adding the maxpoll <value>.

Restart the ntp daemon.

# stopsrc -s xntpd
# startsrc -s xntpd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16406r294075_chk'
  tag severity: 'medium'
  tag gid: 'V-215208'
  tag rid: 'SV-215208r508663_rule'
  tag stig_id: 'AIX7-00-001053'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-16404r294076_fix'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144']
  tag 'documentable'
  tag legacy: ['V-91523', 'SV-101621']
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end

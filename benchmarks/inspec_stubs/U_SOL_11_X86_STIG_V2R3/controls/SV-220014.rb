control 'SV-220014' do
  title 'The operating system must synchronize internal information system clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'To assure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD. Many system functions, including time-based login and activity restrictions, automated reports, system logs, and audit records depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.'
  desc 'check', %q(NTP must be used and used only in the global zone. Determine the zone that you are currently securing.

# zonename

If the command output is not "global", then NTP must be disabled. Check the system for a running NTP daemon.

# svcs -Ho state ntp

If NTP is online, this is a finding.

If the output from "zonename" is "global", then NTP must be enabled. Check the system for a running NTP daemon.

# svcs -Ho state ntp


If NTP is not online, this is a finding.

If NTP is running, confirm the servers and peers or multicast client (as applicable) are local or an authoritative U.S. DoD source.

For the NTP daemon

# more /etc/inet/ntp.conf

If a non-local/non-authoritative (non-U.S. DoD source, non-USNO-based, or non-GPS) time server is used, this is a finding.

Determine if the time synchronization frequency is correct.

# grep "maxpoll" /etc/inet/ntp.conf

If the command returns "File not found" or any value for maxpoll, this is a finding.

Determine if the running NTP server is configured properly.

# ntpq -p | awk '($6 ~ /[0-9]+/ && $6 > 86400) { print $1" "$6 }'

This will print out the name of any time server whose current polling time is greater than 24 hours (along with the actual value). If there is any output, this is a finding.)
  desc 'fix', 'The root role is required.

Determine the zone that you are currently securing.

# zonename

If the command output is not "global", then NTP must be disabled.

# svcadm disable ntp

If the output from "zonename" is "global", then NTP must be enabled.  

To activate the ntpd daemon, the ntp.conf file must first be created.

# cp /etc/inet/ntp.client /etc/inet/ntp.conf

# pfedit /etc/inet/ntp.conf

Make site-specific changes to this file as needed in the form.

server [ntpserver]

Locate the line containing maxpoll (if it exists).
Delete the line.

Start the ntpd daemon.

# svcadm enable ntp

Use a local authoritative time server synchronizing to an authorized DoD time source, a USNO-based time server, or a GPS. Ensure all systems in the facility feed from one or more local time servers that feed from the authoritative time server.

Edit the NTP configuration files and make the necessary changes to add the approved time servers per Solaris documentation.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21724r462448_chk'
  tag severity: 'medium'
  tag gid: 'V-220014'
  tag rid: 'SV-220014r603268_rule'
  tag stig_id: 'SOL-11.1-090020'
  tag gtitle: 'SRG-OS-000356'
  tag fix_id: 'F-21723r462449_fix'
  tag 'documentable'
  tag legacy: ['SV-60857', 'V-47985']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

control 'SV-226434' do
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc 'To assure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD. Many system functions, including time-based login and activity restrictions, automated reports, system logs, and audit records depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

Authoritative time sources include authorized time servers within the enclave that synchronize with upstream authoritative sources. Specific requirements for the upstream synchronization of Network Time Protocol (NTP) servers are covered in the Network Other Devices STIG.

For systems located on isolated or closed networks, it is not necessary to synchronize with a global authoritative time source. If a global authoritative time source is not available to systems on an isolated network, a local authoritative time source must be established on this network and used by the systems connected to this network. This is necessary to provide the ability to correlate events and allow for the correct operation of time-dependent protocols between systems on the isolated network.

If the system is completely isolated (no connections to networks or other systems), time synchronization is not required as no correlation of events between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'NTP must be used and used only in the global zone. Determine the zone that you are currently securing.

# zonename

If the command output is not "global", NTP must be disabled. Check the system for a running NTP daemon.

# svcs ntp | grep online

If the output from "zonename" is "global", NTP must be enabled. Check the system for a running NTP daemon.

# svcs ntp | grep online

If NTP is not online, this is a finding.

If NTP is running confirm the servers and peers or multicast client (as applicable) are local or an authoritative U.S. DoD source.

# more /etc/inet/ntp.conf

If a non-local/non-authoritative (U.S. DoD source) time-server is used, this is a finding.'
  desc 'fix', 'Use a local authoritative time server synchronizing to an authorized DoD time source. Ensure all systems in the facility feed from one or more local time servers that feed from the authoritative time server.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28595r482666_chk'
  tag severity: 'medium'
  tag gid: 'V-226434'
  tag rid: 'SV-226434r603265_rule'
  tag stig_id: 'GEN000240'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-28583r482667_fix'
  tag 'documentable'
  tag legacy: ['V-4301', 'SV-40040']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

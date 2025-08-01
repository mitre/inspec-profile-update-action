control 'SV-218193' do
  title 'The system clock must be synchronized to an authoritative DoD time source.'
  desc 'To assure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD.  Many system functions, including time-based login and activity restrictions, automated reports, system logs, and audit records depend on an accurate system clock.  If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

Authoritative time sources include authorized time servers within the enclave that synchronize with upstream authoritative sources.  Specific requirements for the upstream synchronization of network time protocol (NTP) servers are covered in the Network Other Devices STIG.

For systems located on isolated or closed networks, it is not necessary to synchronize with a global authoritative time source.  If a global authoritative time source is not available to systems on an isolated network, a local authoritative time source must be established on this network and used by the systems connected to this network.  This is necessary to provide the ability to correlate events and allow for the correct operation of time-dependent protocols between systems on the isolated network.

If the system is completely isolated (i.e., it has no connections to networks or other systems), time synchronization is not required as no correlation of events between systems will be necessary. If the system is completely isolated, this requirement is not applicable.'
  desc 'check', 'Check if NTP running:
# ps -ef | egrep "xntpd|ntpd"

Check if "ntpd -qg" scheduled to run:
# grep "ntpd -qg" /var/spool/cron/*
# grep "ntpd -qg" /etc/cron.d/*
# grep "ntpd -qg" /etc/cron.daily/*
# grep "ntpd -qg" /etc/cron.hourly/*
# grep "ntpd -qg" /etc/cron.monthly/*
# grep "ntpd -qg" /etc/cron.weekly/*

If NTP is running or "ntpd -qg" is found:

# more /etc/ntp.conf

Confirm the timeservers and peers or multicast client (as applicable) are local or authoritative U.S. DoD sources appropriate for the level of classification which the network operates.

If a non-local/non-authoritative time-server is used, this is a finding.'
  desc 'fix', 'Use an authoritative local time server or a time server operated by the U.S. government.  Ensure all systems in the facility feed from one or more local time servers which feed from the authoritative U.S. government time server.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19668r568516_chk'
  tag severity: 'medium'
  tag gid: 'V-218193'
  tag rid: 'SV-218193r603259_rule'
  tag stig_id: 'GEN000240'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-19666r568517_fix'
  tag 'documentable'
  tag legacy: ['V-4301', 'SV-63137']
  tag cci: ['CCI-001492', 'CCI-001891']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (a)']
end

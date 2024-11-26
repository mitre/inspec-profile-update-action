control 'SV-223551' do
  title 'IBM z/OS SNTP daemon (SNTPD) permission bits must be properly configured.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time, a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'From the ISPF Command Shell enter:
cd /usr/sbin
ls -al

If the following File permission and user Audit Bits are true, this is not a finding.

/usr/sbin/sntpd 1740 faf

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:
f log for failed access attempts
a log for failed and successful access
- no auditing'
  desc 'fix', 'With the assistance of a systems programmer with UID(0) and/or SUPERUSER access, configure the UNIX permission bits and user audit bits on the SNTPD to conform to the specifications below:

/usr/sbin/sntpd 1740 faf'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25224r500788_chk'
  tag severity: 'medium'
  tag gid: 'V-223551'
  tag rid: 'SV-223551r877038_rule'
  tag stig_id: 'ACF2-OS-000150'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-25212r500789_fix'
  tag 'documentable'
  tag legacy: ['V-97807', 'SV-106911']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end

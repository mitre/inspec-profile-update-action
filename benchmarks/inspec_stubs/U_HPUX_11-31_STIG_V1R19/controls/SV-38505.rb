control 'SV-38505' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all device special files existing anywhere on the system. Types include: b=block, c=character, p=fifo.

Example:
# find / -type b -print >> devicelist
# find / -type c -print >> devicelist
# find / -type p -print >> devicelist

Check the permissions on the directories above subdirectories that contain device files. If any device file, or directory containing device files, is world-writable, except device files specifically intended to be world-writable such as /dev/null, this is a finding.

Note the following exception/exclusion list:

/dev/pts/*, /dev/pty/*, /dev/ptym/*, the following in dev: full, zero, null, tty, ptmx, pty*, tcp, udp, ip, arp, udp6, tcp6, rawip6, ip6, rawip, rtsock, ipsecpol, ipseckey, sad, dlpi*, sasd*, ttyp*, ttyq*, ttyr*, strlog, telnetm, tlclts, asyncdsk, async, tlcots, tlcotsod, echo, beep, gvid0, gvid, poll, log, log.um, stcpmap, nuls, usctp6, sctp6, usctp, syscon, and sctp.'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36415r2_chk'
  tag severity: 'medium'
  tag gid: 'V-924'
  tag rid: 'SV-38505r2_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'GEN002280'
  tag fix_id: 'F-31753r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

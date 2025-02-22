control 'SV-226573' do
  title 'Device files and directories must only be writable by users with a system account or as configured by the vendor.'
  desc 'System device files in writable directories could be modified, removed, or used by an unprivileged user to control system hardware.'
  desc 'check', 'Find all device files existing anywhere on the system.

Procedure:
# find / -type b -print > devicelist
# find / -type c -print >> devicelist

Check the permissions on the directories above subdirectories containing device files. 



The following list of device files are intended to be world-writable and if present are not a finding. 



/dev/arp
/dev/conslog
/dev/crypto
/dev/dtrace/dtrace
/dev/dtrace/helper
/dev/dtrace/provider/fasttrap
/dev/fd/*
/dev/kstat
/dev/null
/dev/poll
/dev/pool
/dev/ptmx
/dev/sad/user
/dev/tcp
/dev/tcp6
/dev/ticlts
/dev/ticots
/dev/ticotsord
/dev/tty
/dev/udp
/dev/udp6
/dev/zero
/dev/zfs


If any device file or their parent directory is world-writable and it is not intended to be world-writable, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from the device file(s).

Procedure:
# chmod o-w <device file>

Document all changes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28734r483128_chk'
  tag severity: 'medium'
  tag gid: 'V-226573'
  tag rid: 'SV-226573r603265_rule'
  tag stig_id: 'GEN002280'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28722r483129_fix'
  tag 'documentable'
  tag legacy: ['V-924', 'SV-924']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

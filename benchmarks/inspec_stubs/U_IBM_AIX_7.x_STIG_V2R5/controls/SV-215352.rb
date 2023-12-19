control 'SV-215352' do
  title 'If NFS is not required on AIX, the NFS daemon must be disabled.'
  desc 'The rcnfs entry starts the NFS daemons during system boot.

NFS is a service with numerous historical vulnerabilities and should not be enabled unless there is no alternative. If NFS serving is required, then read-only exports are recommended and no filesystem or directory should be exported with root access. Unless otherwise required the NFS daemons (rcnfs) will be disabled.'
  desc 'check', 'From the command prompt, execute the following command:
# lsitab rcnfs

If the command yields any output, this is a finding.'
  desc 'fix', 'In "/etc/inittab", remove the "rcnfs" entry by running the following command:
# rmitab rcnfs

To request the init command to re-examine the "/etc/inittab" file, enter: 
# telinit q'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16550r294507_chk'
  tag severity: 'medium'
  tag gid: 'V-215352'
  tag rid: 'SV-215352r508663_rule'
  tag stig_id: 'AIX7-00-003046'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16548r294508_fix'
  tag 'documentable'
  tag legacy: ['V-91329', 'SV-101427']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

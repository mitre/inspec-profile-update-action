control 'SV-90679' do
  title 'The OS X system must be configured to disable the Network File System (NFS) daemon unless it is required.'
  desc 'If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is non-essential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'If the NFS daemon is required, this is not applicable.

To check if the NFS daemon is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd

If the results do not show the following, this is a finding:

"com.apple.nfsd" => true'
  desc 'fix', 'To disable the NFS daemon, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.nfsd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75991'
  tag rid: 'SV-90679r1_rule'
  tag stig_id: 'AOSX-12-000141'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

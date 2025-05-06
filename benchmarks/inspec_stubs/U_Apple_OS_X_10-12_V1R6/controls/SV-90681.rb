control 'SV-90681' do
  title 'The OS X system must be configured to disable the Network File System (NFS) lock daemon unless it is required.'
  desc 'If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is non-essential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'If the NFS lock daemon is required, this is not applicable.

To check if the NFS lock daemon is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.lockd

If the results do not show the following, this is a finding:

"com.apple.lockd" => true'
  desc 'fix', 'To disable the NFS lock daemon, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.lockd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75993'
  tag rid: 'SV-90681r1_rule'
  tag stig_id: 'AOSX-12-000142'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-257186' do
  title 'The macOS system must be configured to disable the Network File System (NFS) daemon unless it is required.'
  desc 'If the system does not require access to NFS file shares or is not acting as an NFS server, support for NFS is nonessential and NFS services must be disabled. NFS is a network file system protocol supported by UNIX-like operating systems. Enabling any service increases the attack surface for an intruder. By disabling unnecessary services, the attack surface is minimized.'
  desc 'check', 'Verify the macOS system is configured to disable the NFS daemon with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.apple.nfsd

"com.apple.nfsd" => disabled

If the results are not "com.apple.nfsd => disabled" or the use of NFS has not been documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the NFS daemon with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.nfsd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60871r905189_chk'
  tag severity: 'medium'
  tag gid: 'V-257186'
  tag rid: 'SV-257186r905191_rule'
  tag stig_id: 'APPL-13-002003'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60812r905190_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-250580' do
  title 'All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The shells file lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure. By default, the shells file contains the only shell files in the ESXi file system, /bin/ash and /bin/sh. Users not granted shell access are assigned the shell /sbin/nologin.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell.
<file> = /etc/shells

Available shells for ESXi are "/bin/sh" and "/bin/ash".

Execute the following command(s):
# ls -lL `cat /etc/shells`

If /etc/shells does not exist, this is a finding.

If /etc/shells exists and is empty, this is a finding.

If /etc/shells exists and includes both the /bin/sh and /bin/ash shells, this is not a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. 
Enable the ESXi Shell.
<file> = /etc/shells
Available shells for ESXi are "/bin/sh" and "/bin/ash".

Ensure both the above interactive shell(s) are listed in the /etc/shells file. If necessary, add them:
# vi /etc/shells

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54015r798737_chk'
  tag severity: 'medium'
  tag gid: 'V-250580'
  tag rid: 'SV-250580r798739_rule'
  tag stig_id: 'GEN002140-ESXI5-000046'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53969r798738_fix'
  tag 'documentable'
  tag legacy: ['SV-51092', 'V-39276']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

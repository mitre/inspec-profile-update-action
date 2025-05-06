control 'SV-250575' do
  title 'The root accounts executable search path must be the vendor default and must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell.
<file> = /etc/profile
<required_keyword> = PATH
<required_keyword_setpoint> = /bin:/sbin

Execute the following command(s):
# grep PATH /etc/profile

If the "PATH" is not set to "/bin:/sbin", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.
<file> = /etc/profile
<required_keyword> = PATH
<required_keyword_setpoint> = /bin:/sbin
Execute the following command(s):
# vi /etc/profile

Set the "PATH" to "/bin:/sbin".

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54010r798722_chk'
  tag severity: 'medium'
  tag gid: 'V-250575'
  tag rid: 'SV-250575r798724_rule'
  tag stig_id: 'GEN000940-ESXI5-000042'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53964r798723_fix'
  tag 'documentable'
  tag legacy: ['V-39273', 'SV-51089']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

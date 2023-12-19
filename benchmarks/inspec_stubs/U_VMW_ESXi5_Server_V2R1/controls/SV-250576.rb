control 'SV-250576' do
  title 'The root accounts library search path must be the system default and must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', 'Disable lock down mode.
Enable the ESXi Shell.
<file> = /etc/vmware/config
<required_keyword> = libdir
<required_keyword_setpoint> = /usr/lib/vmware

Execute the following command(s):
# grep libdir /etc/vmware/config

If the "libdir" path is not set to "/usr/lib/vmware", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.
<file> = /etc/vmware/config
<required_keyword> = libdir
<required_keyword_setpoint> = /usr/lib/vmware
Execute the following command(s):
# vi /etc/vmware/config

Set the "libdir" path to "/usr/lib/vmware".

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54011r798725_chk'
  tag severity: 'medium'
  tag gid: 'V-250576'
  tag rid: 'SV-250576r798727_rule'
  tag stig_id: 'GEN000945-ESXI5-000333'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53965r798726_fix'
  tag 'documentable'
  tag legacy: ['SV-51240', 'V-39382']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

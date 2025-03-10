control 'SV-248630' do
  title 'OL 8 must disable acquiring, saving, and processing core dumps.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems. 
 
When the kernel invokes "systemd-coredump" to handle a core dump, it runs in privileged mode and will connect to the socket created by the "systemd-coredump.socket" unit. This, in turn, will spawn an unprivileged "systemd-coredump@.service" instance to process the core dump.'
  desc 'check', 'Verify OL 8 is not configured to acquire, save, or process core dumps with the following command: 
 
$ sudo systemctl status systemd-coredump.socket 
 
systemd-coredump.socket 
Loaded: masked (Reason: Unit systemd-coredump.socket is masked.) 
Active: inactive (dead) 
 
If the "systemd-coredump.socket" is loaded and not masked and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the system to disable the "systemd-coredump.socket" with the following commands:

$ sudo systemctl disable --now systemd-coredump.socket

$ sudo systemctl mask systemd-coredump.socket

Created symlink /etc/systemd/system/systemd-coredump.socket -> /dev/null'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52064r779454_chk'
  tag severity: 'medium'
  tag gid: 'V-248630'
  tag rid: 'SV-248630r779456_rule'
  tag stig_id: 'OL08-00-010672'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52018r779455_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

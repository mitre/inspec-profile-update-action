control 'SV-99939' do
  title 'Lighttpd must protect against or limit the effects of HTTP types of Denial of Service (DoS) attacks.'
  desc 'In UNIX and related computer operating systems, a file descriptor is an indicator used to access a file or other input/output resource, such as a pipe or network connection. File descriptors index into a per-process file descriptor table maintained by the kernel, that in turn indexes into a system-wide table of files opened by all processes, called the file table.

As a single-threaded server, Lighttpd must be limited in the number of file descriptors that can be allocated. This will prevent Lighttpd from being used in a form of DoS attack against the Operating System.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^server.max-fds' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value for "server.max-fds" is not set to "2048", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following: 

server.max-fds = 2048'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89289'
  tag rid: 'SV-99939r1_rule'
  tag stig_id: 'VRAU-LI-000335'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-96031r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end

control 'SV-240060' do
  title 'HAProxy must be run in a chroot jail.'
  desc 'Chroot is an operation that changes the apparent root directory for the current running process and their children. A program that is run in such a modified environment cannot access files and commands outside that environmental directory tree. This modified environment is called a chroot jail.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'chroot' /etc/haproxy/haproxy.cfg

If the value "/var/lib/haproxy" is not listed, this is a finding.)
  desc 'fix', "Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to and configure the globals section with the following value:

'chroot /var/lib/haproxy'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43293r665347_chk'
  tag severity: 'medium'
  tag gid: 'V-240060'
  tag rid: 'SV-240060r879587_rule'
  tag stig_id: 'VRAU-HA-000175'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-43252r665348_fix'
  tag 'documentable'
  tag legacy: ['SV-99807', 'V-89157']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

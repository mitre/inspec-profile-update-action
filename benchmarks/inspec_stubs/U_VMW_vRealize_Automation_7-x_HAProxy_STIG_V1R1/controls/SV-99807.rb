control 'SV-99807' do
  title 'HAProxy must be run in a chroot jail.'
  desc 'Chroot is an operation that changes the apparent root directory for the current running process and their children. A program that is run in such a modified environment cannot access files and commands outside that environmental directory tree. This modified environment is called a chroot jail.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'chroot' /etc/haproxy/haproxy.cfg

If the value "/var/lib/haproxy" is not listed, this is a finding.)
  desc 'fix', "Navigate to and open /etc/haproxy/haproxy.cfg

Navigate to and configure the globals section with the following value:

'chroot /var/lib/haproxy'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89157'
  tag rid: 'SV-99807r1_rule'
  tag stig_id: 'VRAU-HA-000175'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-95899r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

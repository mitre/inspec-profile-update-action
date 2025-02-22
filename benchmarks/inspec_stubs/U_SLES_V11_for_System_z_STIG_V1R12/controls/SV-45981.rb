control 'SV-45981' do
  title 'The IPv6 protocol handler must be prevented from dynamic loading unless needed.'
  desc 'IPv6 is the next generation of the Internet protocol.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If this system uses IPv6, this is not applicable.

Verify the IPv6 protocol handler is prevented from dynamic loading.
# /sbin/ifconfig | grep –i inet6
This command should not return any output.  If any lines are returned that display IPv6 addresses associated with the TCP/IP stack, this is a finding.'
  desc 'fix', 'Comment or remove any IPV6 specific entries in the /etc/hosts file.  On a standard SLES system, those entries would be something like:
   # special IPv6 addresses
   # ::1             localhost ipv6-localhost ipv6-loopback

   # fe00::0         ipv6-localnet'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22542'
  tag rid: 'SV-45981r1_rule'
  tag stig_id: 'GEN007720'
  tag gtitle: 'GEN007720'
  tag fix_id: 'F-39346r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

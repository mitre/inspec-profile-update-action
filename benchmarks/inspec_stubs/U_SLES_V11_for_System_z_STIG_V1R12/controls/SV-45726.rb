control 'SV-45726' do
  title 'The system must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated.  An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the system does not accept IPv4 ICMP redirect messages.

# grep [01] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep "default|all"

If all of the resulting lines do not end with "0", this is a finding.'
  desc 'fix', 'Configure the system to not accept IPv4 ICMP redirect messages.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.accept_redirects=0" and "net.ipv4.conf.default.accept_redirects=0".
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22416'
  tag rid: 'SV-45726r1_rule'
  tag stig_id: 'GEN003609'
  tag gtitle: 'GEN003609'
  tag fix_id: 'F-39124r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001503', 'CCI-001551']
  tag nist: ['CM-6 d', 'AC-4']
end

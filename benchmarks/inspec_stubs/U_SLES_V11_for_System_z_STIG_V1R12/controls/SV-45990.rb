control 'SV-45990' do
  title 'The system must ignore IPv6 ICMP redirect messages.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack."
  desc 'check', 'Verify the system is configured to ignore IPv6 ICMP redirect messages.
# cat /proc/sys/net/ipv6/conf/all/accept_redirects

If the /proc/sys/net/ipv6/conf/all/accept_redirects entry does not exist because of compliance with GEN007720, this is not a finding.

If the returned value is not "0", this is a finding.'
  desc 'fix', 'Configure the system to ignore IPv6 ICMP redirect messages.
Edit "/etc/sysctl.conf" and add a settings for "net.ipv6.conf.default.accept_redirects=0" and "net.ipv6.conf.all.accept_redirects=0". 
Restart the system for the setting to take effect.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43272r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22550'
  tag rid: 'SV-45990r2_rule'
  tag stig_id: 'GEN007860'
  tag gtitle: 'GEN007860'
  tag fix_id: 'F-39355r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

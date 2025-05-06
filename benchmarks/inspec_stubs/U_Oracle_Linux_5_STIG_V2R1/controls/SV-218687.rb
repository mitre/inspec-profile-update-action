control 'SV-218687' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20162r556478_chk'
  tag severity: 'medium'
  tag gid: 'V-218687'
  tag rid: 'SV-218687r603259_rule'
  tag stig_id: 'GEN007860'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-20160r556479_fix'
  tag 'documentable'
  tag legacy: ['V-22550', 'SV-63401']
  tag cci: ['CCI-000382', 'CCI-001551', 'CCI-001503']
  tag nist: ['CM-7 b', 'AC-4', 'CM-6 d']
end

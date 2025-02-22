control 'SV-218481' do
  title 'The system must not process Internet Control Message Protocol (ICMP)  timestamp requests.'
  desc 'The processing of (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', %q(Verify the system does not respond to ICMP TIMESTAMP-REQUESTs

Procedure:
# grep "timestamp" /etc/sysconfig/iptables

This should return entries for "timestamp-reply" and "timestamp-request". Both should end with "-j DROP'. If either does not exist or does not "DROP" the message, this is a finding.)
  desc 'fix', 'Configure the system to not respond to ICMP TIMESTAMP-REQUESTs. This is done by rejecting ICMP type 13 and 14 messages at the firewall.

Procedure:
Edit /etc/sysconfig/iptables to add:

-A RH-Firewall-1-INPUT -p ICMP --icmp-type timestamp-request -j DROP
-A RH-Firewall-1-INPUT -p ICMP --icmp-type timestamp-reply -j DROP

Restart the firewall:
# service iptables restart'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19956r555641_chk'
  tag severity: 'low'
  tag gid: 'V-218481'
  tag rid: 'SV-218481r603259_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-19954r555642_fix'
  tag 'documentable'
  tag legacy: ['V-22409', 'SV-64445']
  tag cci: ['CCI-000382', 'CCI-001551', 'CCI-001503']
  tag nist: ['CM-7 b', 'AC-4', 'CM-6 d']
end

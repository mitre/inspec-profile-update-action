control 'SV-45721' do
  title 'The system must not process Internet Control Message Protocol (ICMP)  timestamp requests.'
  desc 'The processing of (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', 'Verify the system does not respond to ICMP TIMESTAMP_REQUESTs

Procedure:

# iptables -L INPUT | grep "timestamp"


This should return the following entries for "timestamp-reply" and "timestamp_request":
DROP       icmp --  anywhere             anywhere            icmp timestamp-request 
DROP       icmp --  anywhere             anywhere            icmp timestamp-reply

If either does not exist or does not "DROP" the message, this is a finding.'
  desc 'fix', %q(Configure the system to not respond to ICMP TIMESTAMP_REQUESTs. This is done by rejecting ICMP type 13 and 14 messages at the firewall.

Procedure:

1. Check the SuSEfirewall2 configuration to see if custom rules are being used:

# grep -v '^#' /etc/sysconfig/SuSEfirewall2 | grep FW_CUSTOMRULES

If the command returns FW_CUSTOMRULES=”” then no custom rules are being used.  In that case edit the /etc/sysconfig/SuSEfirewall2 file and use the vendor supplied file by setting FW_CUSTOMRULES="/etc/sysconfig/scripts/SuSEfirewall2-custom"

2. Edit the file defined by the FW_CUSTOMRULES variable and add these commands to append the INPUT chain:

iptables -A INPUT -p ICMP --icmp-type timestamp-request -j DROP
iptables -A INPUT -p ICMP --icmp-type timestamp-reply -j DROP

Restart the firewall:

# rcSuSEfirewall2 restart)
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43088r1_chk'
  tag severity: 'low'
  tag gid: 'V-22409'
  tag rid: 'SV-45721r1_rule'
  tag stig_id: 'GEN003602'
  tag gtitle: 'GEN003602'
  tag fix_id: 'F-39119r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

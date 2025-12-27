control 'SV-218718' do
  title 'The systems local firewall must implement a deny-all, allow-by-exception policy.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Check the firewall rules for a default deny rule.

# iptables --list

Example of a rule meeting this criteria:
REJECT    all  --  anywhere          anywhere         reject-with icmp-host-prohibited

A rule using DROP is also acceptable.  The default rule should be the last rule of a table and match all traffic.

If there is no default deny rule, this is a finding.'
  desc 'fix', 'Edit "/etc/sysconfig/iptables" and add a default deny rule.

An example of a default deny rule:
-A RH-Firewall-1-INPUT -j REJECT --reject-with icmp-host-prohibited

Restart the iptable service.
# service iptables restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20193r562942_chk'
  tag severity: 'medium'
  tag gid: 'V-218718'
  tag rid: 'SV-218718r603259_rule'
  tag stig_id: 'GEN008540'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-20191r562943_fix'
  tag 'documentable'
  tag legacy: ['V-22583', 'SV-63141']
  tag cci: ['CCI-001109', 'CCI-002314']
  tag nist: ['SC-7 (5)', 'AC-17 (1)']
end

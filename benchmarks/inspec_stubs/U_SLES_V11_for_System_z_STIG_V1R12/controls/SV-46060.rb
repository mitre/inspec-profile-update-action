control 'SV-46060' do
  title 'The systems local firewall must implement a deny-all, allow-by-exception policy.'
  desc 'A local firewall protects the system from exposing unnecessary or undocumented network services to the local enclave.  If a system within the enclave is compromised, firewall protection on an individual system continues to protect it from attack.'
  desc 'check', 'Check the firewall rules for a default deny rule.
# iptables --list
If there is no default deny rule, this is a finding.'
  desc 'fix', 'Edit “ /etc/sysconfig/scripts/SuSEfirewall2-custom” and add a default deny rule.

Restart the SuSEfirewall2 service
# rcSuSEfirewall2 restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43325r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22583'
  tag rid: 'SV-46060r1_rule'
  tag stig_id: 'GEN008540'
  tag gtitle: 'GEN008540'
  tag fix_id: 'F-39416r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end

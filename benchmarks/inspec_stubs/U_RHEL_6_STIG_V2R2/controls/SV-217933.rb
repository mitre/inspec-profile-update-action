control 'SV-217933' do
  title 'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'
  desc 'In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.'
  desc 'check', 'Run the following command to ensure the default "INPUT" policy is "DROP":

# iptables -nvL | grep -i input

Chain INPUT (policy DROP 0 packets, 0 bytes)

If the default policy for the INPUT chain is not set to DROP, this is a finding.'
  desc 'fix', 'To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/iptables": 

:INPUT DROP [0:0]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19414r376814_chk'
  tag severity: 'medium'
  tag gid: 'V-217933'
  tag rid: 'SV-217933r603264_rule'
  tag stig_id: 'RHEL-06-000120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19412r376815_fix'
  tag 'documentable'
  tag legacy: ['V-38513', 'SV-50314']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

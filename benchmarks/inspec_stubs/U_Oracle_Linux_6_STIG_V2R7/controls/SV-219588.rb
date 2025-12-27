control 'SV-219588' do
  title 'The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'
  desc 'In "ip6tables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.'
  desc 'check', 'If IPv6 is disabled, this is not applicable.

Inspect the file "/etc/sysconfig/ip6tables" to determine the default policy for the INPUT chain. It should be set to DROP:

# grep ":INPUT" /etc/sysconfig/ip6tables

If the default policy for the INPUT chain is not set to DROP, this is a finding.'
  desc 'fix', 'To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/ip6tables":

:INPUT DROP [0:0]

Restart the IPv6 firewall:

# service ip6tables restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21313r462361_chk'
  tag severity: 'medium'
  tag gid: 'V-219588'
  tag rid: 'SV-219588r793845_rule'
  tag stig_id: 'OL6-00-000523'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21312r462362_fix'
  tag 'documentable'
  tag legacy: ['V-50521', 'SV-64727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-219554' do
  title 'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.'
  desc 'In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.'
  desc 'check', 'Inspect the file "/etc/sysconfig/iptables" to determine the default policy for the INPUT chain. It should be set to DROP. 

# grep ":INPUT" /etc/sysconfig/iptables

If the default policy for the INPUT chain is not set to DROP, this is a finding.'
  desc 'fix', 'To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/iptables": 

:INPUT DROP [0:0]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21279r462334_chk'
  tag severity: 'medium'
  tag gid: 'V-219554'
  tag rid: 'SV-219554r793811_rule'
  tag stig_id: 'OL6-00-000120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21278r462335_fix'
  tag 'documentable'
  tag legacy: ['SV-65193', 'V-50987']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

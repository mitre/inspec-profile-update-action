control 'SV-219579' do
  title 'The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.'
  desc 'In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.'
  desc 'check', 'Run the following command to ensure the default "FORWARD" policy is "DROP": 

grep ":FORWARD" /etc/sysconfig/iptables

The output must be the following: 

# grep ":FORWARD" /etc/sysconfig/iptables
:FORWARD DROP [0:0]

If it is not, this is a finding.'
  desc 'fix', 'To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in "/etc/sysconfig/iptables": 

:FORWARD DROP [0:0]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21304r462352_chk'
  tag severity: 'medium'
  tag gid: 'V-219579'
  tag rid: 'SV-219579r793836_rule'
  tag stig_id: 'OL6-00-000320'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21303r462353_fix'
  tag 'documentable'
  tag legacy: ['V-51117', 'SV-65327']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

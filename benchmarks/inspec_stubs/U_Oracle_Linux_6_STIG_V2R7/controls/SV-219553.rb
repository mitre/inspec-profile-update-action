control 'SV-219553' do
  title 'The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'
  desc %q(The "iptables" service provides the system's host-based firewalling capability for IPv4 and ICMP.)
  desc 'check', 'If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the "iptables" service: 

# service iptables status

If the service is not running, it should return the following: 

iptables: Firewall is not running.

If the service is not running, this is a finding.'
  desc 'fix', 'The "iptables" service can be enabled with the following commands: 

# chkconfig iptables on
# service iptables start'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21278r358199_chk'
  tag severity: 'medium'
  tag gid: 'V-219553'
  tag rid: 'SV-219553r793810_rule'
  tag stig_id: 'OL6-00-000117'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21277r358200_fix'
  tag 'documentable'
  tag legacy: ['SV-65185', 'V-50979']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

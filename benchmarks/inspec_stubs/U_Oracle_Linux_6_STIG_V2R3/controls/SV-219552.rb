control 'SV-219552' do
  title 'The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'
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
  tag check_id: 'C-21277r358196_chk'
  tag severity: 'medium'
  tag gid: 'V-219552'
  tag rid: 'SV-219552r603263_rule'
  tag stig_id: 'OL6-00-000116'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21276r358197_fix'
  tag 'documentable'
  tag legacy: ['SV-65109', 'V-50903']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

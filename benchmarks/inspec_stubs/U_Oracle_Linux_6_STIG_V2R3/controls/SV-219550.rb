control 'SV-219550' do
  title 'The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.'
  desc %q(The "ip6tables" service provides the system's host-based firewalling capability for IPv6 and ICMPv6.)
  desc 'check', 'If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service:

# service ip6tables status

If the service is not running, it should return the following:

ip6tables: Firewall is not running.

If the service is not running, this is a finding.'
  desc 'fix', 'The "ip6tables" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21275r358190_chk'
  tag severity: 'medium'
  tag gid: 'V-219550'
  tag rid: 'SV-219550r603263_rule'
  tag stig_id: 'OL6-00-000107'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21274r358191_fix'
  tag 'documentable'
  tag legacy: ['SV-64987', 'V-50781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

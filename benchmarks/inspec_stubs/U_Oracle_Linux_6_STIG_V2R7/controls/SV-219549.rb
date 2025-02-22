control 'SV-219549' do
  title 'The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.'
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
  tag check_id: 'C-21274r358187_chk'
  tag severity: 'medium'
  tag gid: 'V-219549'
  tag rid: 'SV-219549r793806_rule'
  tag stig_id: 'OL6-00-000106'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21273r358188_fix'
  tag 'documentable'
  tag legacy: ['SV-64973', 'V-50767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

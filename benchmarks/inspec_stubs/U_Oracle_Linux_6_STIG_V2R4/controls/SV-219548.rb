control 'SV-219548' do
  title 'The system must employ a local IPv6 firewall.'
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
  tag check_id: 'C-21273r358184_chk'
  tag severity: 'medium'
  tag gid: 'V-219548'
  tag rid: 'SV-219548r603263_rule'
  tag stig_id: 'OL6-00-000103'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21272r358185_fix'
  tag 'documentable'
  tag legacy: ['SV-64967', 'V-50761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

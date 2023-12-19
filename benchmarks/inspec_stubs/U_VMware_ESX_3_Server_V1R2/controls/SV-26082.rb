control 'SV-26082' do
  title 'The system must log martian packets.'
  desc 'Martian packets are packets containing addresses known by the system to be invalid.  Logging these messages allows the SA to identify misconfigurations or attacks in progress.'
  desc 'check', "Determine if the system is configured to log martian packets.  Consult the vendor documentation to determine if a specific configuration setting is available for this function.  If such a setting is available, and is not enabled, this is a finding.

If no specific configuration is available for the system, check the system's local firewall configuration to determine if there are rules to log inbound traffic containing invalid source addresses, which minimally includes the system's own addresses and broadcast addresses for attached subnets.  If no such rules exist, this is a finding."
  desc 'fix', "Consult vendor documentation to determine if a configuration setting exists to enable the logging of martian packets.  If so, enable this function.

If no such function exists, configure the system's local firewall with rules to log inbound traffic containing invalid source addresses, which minimally includes the system's own addresses and broadcast addresses for attached subnets."
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30376r1_chk'
  tag severity: 'low'
  tag gid: 'V-22418'
  tag rid: 'SV-26082r1_rule'
  tag stig_id: 'GEN003611'
  tag gtitle: 'GEN003611'
  tag fix_id: 'F-27157r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end

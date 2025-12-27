control 'SV-26081' do
  title 'The system must not send IPv4 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination.  These messages contain information from the system's route table that could reveal portions of the network topology."
  desc 'check', 'Determine if the system is configured to send IPv4 ICMP redirect messages.  Consult vendor documentation to determine if the system originates IPv4 ICMP redirect messages and if a specific configuration setting is present and configured correctly.  If no configuration is available, determine if the local firewall is configured to block IPv4 ICMP redirects originating from the system.

If the system originates IPv4 ICMP redirect messages, and is not prevented from sending them through configuration or local firewall settings, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv4 ICMP redirect messages.  Consult vendor documentation for the procedures for configuring the system configuration setting or adding a local firewall rule to prevent the sending of these messages.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29256r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22417'
  tag rid: 'SV-26081r1_rule'
  tag stig_id: 'GEN003610'
  tag gtitle: 'GEN003610'
  tag fix_id: 'F-26275r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

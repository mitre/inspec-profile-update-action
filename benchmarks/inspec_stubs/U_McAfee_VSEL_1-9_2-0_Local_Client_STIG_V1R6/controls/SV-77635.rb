control 'SV-77635' do
  title 'Access to the McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x Web UI must be enforced by firewall rules.'
  desc 'The McAfee VirusScan Enterprise for Linux WEB GUI is the method for configuring the McAfee VSEL on a non-managed Linux system. The WEB GUI on the system could be used maliciously to gain unauthorized access to the system. By restricting access to interface by implementing firewall rules, the risk of unauthorized access will be mitigated.'
  desc 'check', "With the System Administrator's assistance, review the host-based firewall for rules to the McAfee VSEL Web UI's TCP/IP port.

If the host-based firewall does not have rules to restrict access to the McAfee VSEL Web UI, limiting access to specific IP addresses of System Administrators only, determine if the network-based firewall provides for that restriction.

If neither a host-based firewall nor a network-based firewall restricts access to the McAfee VSEL Web UI, this is a finding."
  desc 'fix', 'Configure a host-based firewall or network-based firewall with rules to restrict access to the McAfee VSEL Web UI, limiting access to specific IP addresses of System Administrators only.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Local Client'
  tag check_id: 'C-63897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63145'
  tag rid: 'SV-77635r1_rule'
  tag stig_id: 'DTAVSEL-301'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-69063r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

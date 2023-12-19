control 'SV-221647' do
  title 'The Workspace ONE UEM server must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The MDM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the MDM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the MDM server runs in a cloud or virtualized solution.

'
  desc 'check', 'Review the MDM server platform configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on the MDM server platform, or if it is not configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, this is a finding.'
  desc 'fix', 'Install and configure a DoD-approved firewall to protect the network segment on which the Workspace ONE UEM server is installed.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23362r416779_chk'
  tag severity: 'medium'
  tag gid: 'V-221647'
  tag rid: 'SV-221647r588007_rule'
  tag stig_id: 'VMW1-00-200010'
  tag gtitle: 'PP-MDM-431004'
  tag fix_id: 'F-23351r416780_fix'
  tag satisfies: ['SRG-APP-000142\n\nSFR ID: FMT_SMF.1.1(2) b']
  tag 'documentable'
  tag legacy: ['SV-111293', 'V-102337']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

control 'SV-93715' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. BEMS is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where BEMS runs on a standalone platform. Network firewalls or other architectures may be preferred where BEMS runs in a cloud or virtualized solution.'
  desc 'check', 'Review the BEMS configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on BEMS, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall.'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-79009'
  tag rid: 'SV-93715r1_rule'
  tag stig_id: 'BEMS-00-003800'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-85759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

control 'SV-95781' do
  title 'The BlackBerry UEM server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The BlackBerry UEM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the BlackBerry UEM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the BlackBerry UEM server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Review the BlackBerry UEM server platform configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on the BlackBerry UEM server platform, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81069'
  tag rid: 'SV-95781r1_rule'
  tag stig_id: 'BUEM-12-808700'
  tag gtitle: 'PP-MDM-331004'
  tag fix_id: 'F-87867r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end

control 'SV-101925' do
  title 'The MDM server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The MDM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the MDM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the MDM server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Review the MDM server platform configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on the MDM server platform, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall.'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91823'
  tag rid: 'SV-101925r1_rule'
  tag stig_id: 'MICR-10-300010'
  tag gtitle: 'PP-MDM-331004'
  tag fix_id: 'F-98025r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

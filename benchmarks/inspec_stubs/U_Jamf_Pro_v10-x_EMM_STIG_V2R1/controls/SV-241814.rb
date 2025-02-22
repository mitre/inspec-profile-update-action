control 'SV-241814' do
  title 'The Jamf Pro EMM server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The MDM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality. All others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the MDM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the MDM server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(2) b / CM-7b

'
  desc 'check', 'Review the Jamf Pro EMM server platform configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on the Jamf Pro EMM server platform, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall on the Jamf Pro EMM server.'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45090r685194_chk'
  tag severity: 'medium'
  tag gid: 'V-241814'
  tag rid: 'SV-241814r879588_rule'
  tag stig_id: 'JAMF-10-200010'
  tag gtitle: 'PP-MDM-431004'
  tag fix_id: 'F-45049r685195_fix'
  tag satisfies: ['SRG-APP-000142']
  tag 'documentable'
  tag legacy: ['SV-108689', 'V-99585']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

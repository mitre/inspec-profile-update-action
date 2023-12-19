control 'SV-87861' do
  title 'The Samsung SDS EMM server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The Samsung SDS EMM server is a critical component of the mobility architecture and must be configured to only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the Samsung SDS EMM server runs on a standalone platform. Network firewalls or other architectures may be preferred where the Samsung SDS EMM server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Review the Samsung SDS EMM server platform configuration to determine whether a DoD-approved firewall is installed or if the platform operating system provides a firewall service that can restrict both inbound and outbound traffic by TCP/UDP port and IP address.

If there is not a host-based firewall present on the Samsung SDS EMM server platform, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73209'
  tag rid: 'SV-87861r1_rule'
  tag stig_id: 'SEMM-15-100040'
  tag gtitle: 'PP-MDM-991040'
  tag fix_id: 'F-79655r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

control 'SV-86259' do
  title 'The AirWatch MDM Server platform must be protected by a DoD-approved firewall.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Unneeded services and processes provide additional threat vectors and avenues of attack to the information system. The AirWatch MDM Server is a critical component of the mobility architecture and must be configured to only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A DoD-approved firewall implements the required network restrictions. A host-based firewall is appropriate where the AirWatch MDM Server runs on a standalone platform. Network firewalls or other architectures may be preferred where the AirWatch MDM Server runs in a cloud or virtualized solution.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Review the network configuration of the network segment the AirWatch MDM server appliance is installed on to determine whether a DoD-approved firewall is installed to filter all IP traffic to/from the MDM appliance.

If there is not a firewall present on the network segment the AirWatch MDM server appliance is installed on, or if it is not configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments, this is a finding.'
  desc 'fix', 'Install a DoD-approved firewall to protect the network segment the AirWatch MDM server is installed on.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71635'
  tag rid: 'SV-86259r1_rule'
  tag stig_id: 'VMAW-09-200040'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-77961r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

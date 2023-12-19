control 'SV-86261' do
  title 'The firewall protecting the AirWatch MDM Server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support AirWatch MDM Server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since AirWatch MDM Server is a critical component of the mobility architecture and must be configured to only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the AirWatch MDM Server provides a protection mechanism to ensure unwanted service requests do not reach the AirWatch MDM Server and outbound traffic is limited to only AirWatch MDM Server functionality.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Ask the AirWatch MDM server administrator for a list of ports, protocols and IP address ranges necessary to support MDM server and platform functionality (should also be listed in the STIG Supplemental Procedures document).

Review the host-based firewall and determine if only required ports, protocols and IP address ranges necessary to support MDM server and platform functionality are turned on.

If the network firewall protecting the AirWatch MDM is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the DoD-approved firewall to deny all except for ports listed in the STIG Supplemental document.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 9.x'
  tag check_id: 'C-71967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71637'
  tag rid: 'SV-86261r1_rule'
  tag stig_id: 'VMAW-09-200050'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-77963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

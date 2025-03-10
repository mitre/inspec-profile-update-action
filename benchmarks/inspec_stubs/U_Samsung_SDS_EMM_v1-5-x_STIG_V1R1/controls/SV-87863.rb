control 'SV-87863' do
  title 'The firewall protecting the Samsung SDS EMM server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support Samsung SDS EMM server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since Samsung SDS EMM server is a critical component of the mobility architecture and must be configured to only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the Samsung SDS EMM server provides a protection mechanism to ensure unwanted service requests do not reach the Samsung SDS EMM server and outbound traffic is limited to only Samsung SDS EMM server functionality.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols and IP address ranges necessary to support Samsung SDS EMM server and platform functionality (see the STIG Supplemental document for a list of required ports, protocols, and services).

Review the list to determine if the stated required configuration is appropriate.

Compare the list against the configuration of the firewall, and identify discrepancies.

If the host-based firewall is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on the Samsung SDS EMM server to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73313r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73211'
  tag rid: 'SV-87863r1_rule'
  tag stig_id: 'SEMM-15-100050'
  tag gtitle: 'PP-MDM-991050'
  tag fix_id: 'F-79657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

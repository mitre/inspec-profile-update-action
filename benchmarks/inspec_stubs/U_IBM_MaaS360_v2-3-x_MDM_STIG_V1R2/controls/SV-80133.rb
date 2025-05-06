control 'SV-80133' do
  title 'The firewall protecting the MaaS360 server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support MDM server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since MDM server is a critical component of the mobility architecture and must be configured to only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the MDM server provides a protection mechanism to ensure unwanted service requests do not reach the MDM server and outbound traffic is limited to only MDM server functionality.

SFR ID: FMT_SMF.1.1(1) Refinement'
  desc 'check', 'Review the implementation of the firewall protecting the MaaS360 server with the site system administrator.  Verify  the firewall is configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support the MaaS360 server.

If the firewall protecting the MaaS360 server is not configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support the MaaS360 server, this is a finding.

Note:  Required ports, protocols, and IP address ranges for the MaaS360 MDM are found in the Supplemental document.'
  desc 'fix', 'Configure the DoD-approved firewall to deny all except for ports listed in the STIG Supplemental document.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 v2.3.x MDM'
  tag check_id: 'C-66203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65643'
  tag rid: 'SV-80133r1_rule'
  tag stig_id: 'M360-01-010500'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-71571r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

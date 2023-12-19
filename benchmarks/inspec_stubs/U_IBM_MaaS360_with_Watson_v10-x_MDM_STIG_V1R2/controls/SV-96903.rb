control 'SV-96903' do
  title 'The firewall protecting the MaaS360 server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support MaaS360 server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since MDM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the MDM server provides a protection mechanism to ensure unwanted service requests do not reach the MDM server and outbound traffic is limited to only MDM server functionality.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Ask the MaaS360 administrator for a list of ports, protocols, and IP address ranges necessary to support MaaS360 server and platform functionality. A list can usually be found in the STIG Supplemental document or MDM product documentation.

Compare the list against the configuration of the firewall and identify discrepancies.

If the host-based firewall is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on the MaaS360 server to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82189'
  tag rid: 'SV-96903r1_rule'
  tag stig_id: 'M360-10-200200'
  tag gtitle: 'PP-MDM-331005'
  tag fix_id: 'F-89047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

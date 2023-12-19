control 'SV-95783' do
  title 'The firewall protecting the BlackBerry UEM server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support BlackBerry UEM server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since BlackBerry UEM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the BlackBerry UEM server provides a protection mechanism to ensure unwanted service requests do not reach the BlackBerry UEM server and outbound traffic is limited to only BlackBerry UEM server functionality.

SFR ID: FMT_SMF.1.1(2) b'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols, and IP address ranges necessary to support BlackBerry UEM server and platform functionality. A list can usually be found in the STIG Supplemental document or MDM product documentation.

Compare the list against the configuration of the firewall and identify discrepancies.

If the host-based firewall is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on the BlackBerry UEM server to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80753r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81071'
  tag rid: 'SV-95783r1_rule'
  tag stig_id: 'BUEM-12-808800'
  tag gtitle: 'PP-MDM-331005'
  tag fix_id: 'F-87871r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

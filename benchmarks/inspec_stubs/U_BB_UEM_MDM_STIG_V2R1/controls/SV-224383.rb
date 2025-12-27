control 'SV-224383' do
  title 'The firewall protecting the BlackBerry UEM server platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support BlackBerry UEM server and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since BlackBerry UEM server is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the BlackBerry UEM server provides a protection mechanism to ensure unwanted service requests do not reach the BlackBerry UEM server and outbound traffic is limited to only BlackBerry UEM server functionality.

SFR ID: FMT_SMF.1.1(2) b / CM-7 b

'
  desc 'check', 'Ask the BlackBerry UEM administrator for a list of ports, protocols, and IP address ranges necessary to support BlackBerry UEM server and platform functionality. A list can usually be found in the STIG Supplemental document or BlackBerry UEM product documentation.

Compare the list against the configuration of the firewall and identify discrepancies.

If the host-based firewall is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on the BlackBerry UEM server to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26060r539049_chk'
  tag severity: 'medium'
  tag gid: 'V-224383'
  tag rid: 'SV-224383r604136_rule'
  tag stig_id: 'BUEM-00-200020'
  tag gtitle: 'PP-MDM-431005'
  tag fix_id: 'F-26048r539050_fix'
  tag satisfies: ['SRG-APP-000142']
  tag 'documentable'
  tag legacy: ['SV-111883', 'V-102921']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

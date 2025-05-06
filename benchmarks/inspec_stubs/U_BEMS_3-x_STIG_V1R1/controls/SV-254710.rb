control 'SV-254710' do
  title 'The firewall protecting the BEMS must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support BEMS functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since BEMS is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on BEMS provides a protection mechanism to ensure unwanted service requests do not reach BEMS and outbound traffic is limited to only BEMS functionality.'
  desc 'check', 'Ask the BEMS administrator for a list of ports, protocols, and IP address ranges necessary to support BEMS functionality. A list can usually be found in the STIG Supplemental document or MDM product documentation.

Compare the list against the configuration of the firewall and identify discrepancies.

If the host-based firewall is not configured to support only those ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on BEMS to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58321r861853_chk'
  tag severity: 'medium'
  tag gid: 'V-254710'
  tag rid: 'SV-254710r861855_rule'
  tag stig_id: 'BEMS-03-003900'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-58267r861854_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

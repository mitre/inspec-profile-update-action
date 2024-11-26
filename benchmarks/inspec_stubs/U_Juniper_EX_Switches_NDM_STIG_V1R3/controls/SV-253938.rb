control 'SV-253938' do
  title 'The Juniper EX switch must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if the network device is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

Verify the configuration implements security configuration or implementation guidance using the "show" commands. For example, to review the entire configuration, use "show configuration" from operational mode. If in configuration mode, executing the "show" command will show the configuration of the current hierarchy level. 

If it is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the network device to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

To enable a function or set its configurable parameters, use the "set" command. To disable a function or its configuration parameters, use the "deactivate" or "delete" commands.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57390r843845_chk'
  tag severity: 'medium'
  tag gid: 'V-253938'
  tag rid: 'SV-253938r879887_rule'
  tag stig_id: 'JUEX-NM-000610'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-57341r843846_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-215756' do
  title 'The BIG-IP Core implementation must be configured to remove or disable any functions, ports, protocols, and/or services that are not documented as required.'
  desc 'Unrelated or unneeded proxy services increase the attack vector and add excessive complexity to the securing of the ALG. Multiple application proxies can be installed on many ALGs. However, proxy types must be limited to related functions. At a minimum, the web and email gateway represent different security domains/trust levels. Organizations should also consider separation of gateways that service the DMZ and the trusted network.'
  desc 'check', 'Review the BIG-IP Core configuration to determine if application proxies are installed that are not related to the purpose of the gateway.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Review the Virtual Service List and validate there are only ports listed in the "Service Port" column that are providing proxy services related to the purpose of the BIG-IP Core.

If the BIG-IP Core has unrelated or unneeded application proxy services installed, this is a finding.'
  desc 'fix', 'Configure Virtual Servers in the BIG-IP LTM module with only proxy services that are related to the purpose of the BIG-IP Core.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16948r291081_chk'
  tag severity: 'medium'
  tag gid: 'V-215756'
  tag rid: 'SV-215756r557356_rule'
  tag stig_id: 'F5BI-LT-000069'
  tag gtitle: 'SRG-NET-000131-ALG-000086'
  tag fix_id: 'F-16946r291082_fix'
  tag 'documentable'
  tag legacy: ['SV-74723', 'V-60293']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

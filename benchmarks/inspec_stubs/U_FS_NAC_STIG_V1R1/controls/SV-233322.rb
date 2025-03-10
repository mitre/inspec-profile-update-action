control 'SV-233322' do
  title 'Forescout must deny or restrict access for endpoints that fail critical endpoint security checks.'
  desc 'Devices that do not meet minimum-security configuration requirements pose a risk to the DoD network and information assets.

Endpoint devices must be disconnected or given limited access as designated by the approval authority and system owner if the device fails the authentication or security assessment. The user will be presented with a limited portal, which does not include access options for sensitive resources. Required security checks must implement DoD policy requirements.'
  desc 'check', 'Verify Forescout has been configured to redirect filtered devices to a limited access network to include a remediation network or limited access network.

If a policy does not exist that redirects the failed device to an authorized network for remediation or limited access, this is not a finding.

If the NAC does not deny or restrict access for endpoints that fail critical endpoint security checks, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.

From the Policy tab, check any Pre-Connect policies to ensure devices that fail the baseline security configuration requirements are set to either restrict access to production network, are granted access to only remediation network, or are granted to a limited access network.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36517r605669_chk'
  tag severity: 'medium'
  tag gid: 'V-233322'
  tag rid: 'SV-233322r611394_rule'
  tag stig_id: 'FORE-NC-000140'
  tag gtitle: 'SRG-NET-000322-NAC-001230'
  tag fix_id: 'F-36482r605670_fix'
  tag 'documentable'
  tag cci: ['CCI-002179']
  tag nist: ['AC-3 (8)']
end

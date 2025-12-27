control 'SV-233322' do
  title 'Forescout must deny or restrict access for endpoints that fail critical endpoint security checks. This is required for compliance with C2C Step 4.'
  desc 'Devices that do not meet minimum-security configuration requirements pose a risk to the DoD network and information assets.

Endpoint devices must be disconnected or given limited access as designated by the approval authority and system owner if the device fails the authentication or security assessment. The user will be presented with a limited portal, which does not include access options for sensitive resources. Required security checks must implement DoD policy requirements.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify Forescout has been configured to redirect filtered devices to a limited access network to include a remediation network or limited access network.

If a policy does not exist that redirects the failed device to an authorized network for remediation or limited access, this is not a finding.

If the NAC does not deny or restrict access for endpoints that fail critical endpoint security checks, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure any pre-connect policies to ensure endpoints that fail the baseline security configuration requirements are set to either restrict access or isolate the endpoint.

1. Log on to the Forescout UI.
2. From the Policy tab, check any Pre-Connect policies to ensure devices that fail the baseline security configuration requirements are set to either restrict access to production network, are granted access to only remediation network, or are granted to a limited access network.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36517r811392_chk'
  tag severity: 'medium'
  tag gid: 'V-233322'
  tag rid: 'SV-233322r811393_rule'
  tag stig_id: 'FORE-NC-000140'
  tag gtitle: 'SRG-NET-000322-NAC-001230'
  tag fix_id: 'F-36482r803466_fix'
  tag 'documentable'
  tag cci: ['CCI-002179']
  tag nist: ['AC-3 (8)']
end

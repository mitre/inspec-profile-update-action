control 'SV-242656' do
  title 'The Cisco ISE must be configured to implement cryptographic mechanisms using a FIPS 140-2 validated algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If FIPS Mode is enabled, this is not a finding.

If FIPS mode is not configured, but the Cisco ISE is configured using an alternative manual method to configure to configure configure a FIPS 140-2/3 validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications, this can be lowered to a CAT 2 finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure FIPS 140-2/3 algorithms are used in all security functions requiring cryptographic functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.

NOTE: Configuring FIPS mode is the required DoD configuration. However, this requirement can be lowered to a CAT 2 if the alternative manual configuration is used to configure a FIPS 140-2/3 validated HMAC to protect the integrity of nonlocal maintenance and diagnostic communications.'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45931r864216_chk'
  tag severity: 'high'
  tag gid: 'V-242656'
  tag rid: 'SV-242656r879785_rule'
  tag stig_id: 'CSCO-NM-000510'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-45888r864217_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end

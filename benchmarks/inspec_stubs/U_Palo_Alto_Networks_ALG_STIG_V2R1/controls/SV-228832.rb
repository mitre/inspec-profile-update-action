control 'SV-228832' do
  title 'The Palo Alto Networks security platform, if used to provide intermediary services for remote access communications traffic (TLS or SSL decryption), must ensure inbound and outbound traffic is monitored for compliance with remote access security policies.'
  desc %q(Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS, and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications. With outbound traffic inspection, traffic must be inspected prior to being forwarded to destinations outside of the enclave, such as external email traffic. This requirement does not mandate the decryption and inspection of SSL/TLS; it requires that if this is performed in the device, the decrypted traffic be inspected and conform to security policies.

If SSL/TLS traffic is decrypted in the device, it must be inspected.  The Palo Alto Networks security platform can be configured to decrypt and inspect SSL/TLS connections going through the device.  With SSL Decryption, SSL-encrypted traffic is decrypted and App-ID and the Antivirus, Vulnerability, Anti-Spyware, URL Filtering, and File-Blocking Profiles can be applied to decrypted traffic before being re-encrypted and being forwarded.  This is not limited to SSL encrypted HTTP traffic (HTTPS); other protocols "wrapped" in SSL/TLS can be decrypted and inspected.

Decryption is policy-based and can be used to decrypt, inspect, and control both inbound and outbound SSL and SSH connections. Decryption policies allow the administrator to specify traffic for decryption according to destination, source, or URL category and in order to block or restrict the specified traffic according to security settings.)
  desc 'check', 'If the Palo Alto Networks security platform does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS, and webmail), this is not applicable.

Go to Policies >> Decryption; note each configured decryption policy.
Go to Policies >> Security
View the configured security policies.

If there is a decryption policy that does not have a corresponding security policy, this is a finding.

The matching policy may not be obvious and it may be necessary for the Administrator to identify the corresponding security policy.'
  desc 'fix', 'Note: These instructions assume that certificates have already been loaded on the device.  Multiple decryption policies can be configured; these instructions explain the steps involved but do not provide specific details since the exact local policies are not known.  The Administrator must tailor the configuration to match the site-specific requirements.

Go to Policies >> Decryption
Select "Add".
In the "Decryption Policy Rule" window, complete the required fields.
In the "Name" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" or "Source User" fields.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" or "Destination User" fields.
In the "URL Category" tab, select which categories will be decrypted.
Select "Any" to decrypt all traffic.  This is used for web traffic.
In the "Option" tab, select "Decrypt" as the Action.  Select the decryption profile.
In the Type field, there are three options;
Select "SSL Forward Proxy to decrypt and inspect SSL/TLS traffic from internal users to outside networks".
Select "SSH Proxy to decrypt inbound and outbound SSH connections passing through the device".
Select "SSL Inbound Inspection to decrypt and inspect incoming SSL traffic".

Note: This decryption mode can only work if you have control on the internal server certificate to import the Key Pair on Palo Alto Networks Device.

Decrypted traffic is blocked and restricted according to the policies configured on the firewall.  For each Decryption Policy, there must be a Security Policy in order to inspect and filter the decrypted traffic.  Multiple security policies can be configured; these instructions explain the steps involved but do not provide specific details since the exact local policies are not known.

Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
In the "Name" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.
In the "User" tab, complete the "Source User" and "HIP Profile" fields.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields.
In the "Applications" tab, either select the "Any" check box or add the specific applications.  Configured filters and groups can be selected.
In the "Actions" tab, select the desired resulting action (allow or deny).  If logging of matches on the rule is required, select the "Log forwarding" profile, and select "Log at Session End".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31067r513791_chk'
  tag severity: 'medium'
  tag gid: 'V-228832'
  tag rid: 'SV-228832r557387_rule'
  tag stig_id: 'PANW-AG-000015'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-31044r513792_fix'
  tag 'documentable'
  tag legacy: ['SV-77037', 'V-62547']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

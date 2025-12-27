control 'SV-258598' do
  title 'The ICS must be configured to implement cryptographic mechanisms using a FIPS 140-2/3 approved algorithm.'
  desc 'This configuration protects to protect the confidentiality of Web UI session and guards against DoS attacks. 

This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.

When JITC and FIPS mode is enabled, it enables DoS attacks such as flooding and replay attack audit logs inherently. JITC and FIPS mode are required for ICS use in DOD.'
  desc 'check', 'Verify all settings to ensure only FIPS 140-2/3 algorithms are enabled. 

In the ICS Web UI, navigate to System >> Configuration >> Security >> Inbound SSL Options.
1. Verify "Turn on JITC mode" checkbox is enabled (checked).
2. Verify "Turn on NDcPP mode" checkbox is enabled (checked).
3. Verify "Turn on FIPS mode" checkbox is enabled (checked).

If the use of FIPS 140-2 approved algorithms is not enabled, this is a finding.'
  desc 'fix', 'Enable compliance modes to ensure only FIPS 140-2/3 algorithms are used and to guard against DoS attacks. JITC, NDcPP, and FIPS modes are required for ICS use in DOD.

In the ICS Web UI, navigate to System >> Configuration >> Security >> Inbound SSL Options.
1. Under "DOD Certification Option", check (enabled) "Turn on JITC mode" to enable the JITC mode security features.
2. Once "Turn on JITC mode" is checked, "Turn on NDcPP mode" and "Turn on FIPS mode" are also checked automatically.
3. Click "Save changes" and confirm after the web UI asks for SSL cipher configuration changes.'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62338r930480_chk'
  tag severity: 'high'
  tag gid: 'V-258598'
  tag rid: 'SV-258598r930482_rule'
  tag stig_id: 'IVCS-NM-000010'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-62247r930481_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end

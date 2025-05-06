control 'SV-96079' do
  title 'The WebSphere Application Server must utilize FIPS 140-2-approved encryption modules when authenticating users and processes.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the application server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. 

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.

'
  desc 'check', 'From administrative console, click Security >> SSL certificate and key management >> Manage FIPS.

If "Enable FIPS 140-2" is not selected, this is a finding.'
  desc 'fix', 'From administrative console, click Security >> SSL certificate and key management >> Manage FIPS.

Check "Enable FIPS 140-2".

Click "Save".

Synchronize with the nodes.

Restart all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81075r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81365'
  tag rid: 'SV-96079r1_rule'
  tag stig_id: 'WBSP-AS-001290'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-88151r1_fix'
  tag satisfies: ['SRG-APP-000179-AS-000129', 'SRG-APP-000440-AS-000167', 'SRG-APP-000442-AS-000259', 'SRG-APP-000439-AS-000155', 'SRG-APP-000224-AS-000152', 'SRG-APP-000514-AS-000136', 'SRG-APP-000416-AS-000140']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002418', 'CCI-002421', 'CCI-002422', 'CCI-002450']
  tag nist: ['IA-7', 'SC-23 (3)', 'SC-8', 'SC-8 (1)', 'SC-8 (2)', 'SC-13 b']
end

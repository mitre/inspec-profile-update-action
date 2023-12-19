control 'SV-258461' do
  title 'The EMM system supporting the Google Android 13 BYOAD must be configured for autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and the work profile can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure.

Examples of possible EMM security controls are as follows:
1. Device access restrictions: Restrict or isolate access based on the devices access type (i.e., from the internet), authentication type (e.g., password), credential strength, etc.
2. User and device activity monitoring: Configured to detect anomalous activity, malicious activity, and unauthorized attempts to access DOD information.
3. Device health tracking: Monitor device attestation, health, and agents reporting compromised applications, connections, intrusions, and/or signatures.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)ii, 3.b.(2)ii.1 & 2).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the Google Android 13 BYOAD has been configured to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline. The exact procedure will depend on the EMM system used at the site.

If the EMM system supporting the Google Android 13 BYOAD has not been configured to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices, this is a finding.'
  desc 'fix', 'Configure the EMM system supporting the Google Android 13 BYOAD to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62201r929197_chk'
  tag severity: 'medium'
  tag gid: 'V-258461'
  tag rid: 'SV-258461r929199_rule'
  tag stig_id: 'GOOG-13-800200'
  tag gtitle: 'PP-BYO-000020'
  tag fix_id: 'F-62110r929198_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

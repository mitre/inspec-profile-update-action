control 'SV-257085' do
  title 'The EMM system supporting the iOS/iPadOS 16 BYOAD must be configured for autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline.'
  desc %q(DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and managed data and apps can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure.

Examples of possible EMM security controls are as follows:
1. Device access restrictions: Restrict or isolate access based on the device's access type (i.e., from the internet), authentication type (e.g., password), credential strength, etc.
2. User and device activity monitoring: Configured to detect anomalous activity, malicious activity, and unauthorized attempts to access DOD information.
3. Device health tracking: Monitor device attestation, health, and agents reporting compromised applications, connections, intrusions, and/or signatures.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(3)ii, 3.b.(2)ii,1 and 2.

SFR ID: FMT_SMF_EXT.1.1 #47)
  desc 'check', 'Verify the EMM system supporting the iOS/iPadOS 16 BYOAD has been configured to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline. The exact procedure will depend on the EMM system used at the site.

If the EMM system supporting the iOS/iPadOS 16 BYOAD has not been configured to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices, this is a finding.'
  desc 'fix', 'Configure the EMM system supporting the iOS/iPadOS 16 BYOAD to conduct autonomous monitoring, compliance, and validation to ensure security/configuration settings of mobile devices do not deviate from the approved configuration baseline. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60770r903998_chk'
  tag severity: 'medium'
  tag gid: 'V-257085'
  tag rid: 'SV-257085r904000_rule'
  tag stig_id: 'AIOS-16-800020'
  tag gtitle: 'PP-BYO-000020'
  tag fix_id: 'F-60711r903999_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

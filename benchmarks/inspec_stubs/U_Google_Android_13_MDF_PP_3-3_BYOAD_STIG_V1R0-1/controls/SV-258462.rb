control 'SV-258462' do
  title 'The EMM system supporting the Google Android 13 BYOAD must be configured to initiate autonomous monitoring, compliance, and validation prior to granting the Google Android 13 BYOAD access to DOD information and IT resources.'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and the work profile can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)iii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the Google Android 13 BYOAD has been configured to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources. The exact procedure will depend on the EMM system used at the site.

If the EMM system supporting the Google Android 13 BYOAD has not been configured to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources, this is a finding.'
  desc 'fix', 'Configure the EMM system supporting the Google Android 13 BYOAD to initiate autonomous monitoring, compliance, and validation prior to granting the BYOAD access to DOD information and IT resources. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62202r929200_chk'
  tag severity: 'medium'
  tag gid: 'V-258462'
  tag rid: 'SV-258462r929202_rule'
  tag stig_id: 'GOOG-13-800300'
  tag gtitle: 'PP-BYO-000030'
  tag fix_id: 'F-62111r929201_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

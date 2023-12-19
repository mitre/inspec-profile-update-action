control 'SV-258463' do
  title 'The EMM system supporting the Google Android 13 BYOAD must be configured to detect if the Google Android 13 BYOAD native security controls are disabled.'
  desc 'Examples of indicators that the native device native security controls have been disabled include jailbroken or rooted devices.

DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and the work profile can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure. Detection via collecting and analysis of BYOAD generated logs for noncompliance indicators is acceptable.

This detection capability must be implemented prior to BYOAD access to DOD information and IT resources and continuously monitored on the DOD-managed segment of the BYOAD enrolled in the program. If non-DOD information (i.e., personal user data, device information) outside the DOD-managed segment of the BYOAD is required to be accessed, collected, monitored, tracked (i.e., location), or maintained, the circumstances under which this may be done must be outlined in the user agreement.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)iii).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the EMM system supporting the Google Android 13 BYOAD has been configured to detect if the BYOAD native security controls are disabled. The exact procedure will depend on the EMM system used at the site.

If the EMM system supporting the Google Android 13 BYOAD is not configured to detect if the BYOAD native security controls are disabled, this is a finding.'
  desc 'fix', 'Configure the EMM system supporting the Google Android 13 BYOAD to detect if the BYOAD native security controls are disabled. The exact procedure will depend on the EMM system used at the site.'
  impact 0.5
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62203r929203_chk'
  tag severity: 'medium'
  tag gid: 'V-258463'
  tag rid: 'SV-258463r929205_rule'
  tag stig_id: 'GOOG-13-800400'
  tag gtitle: 'PP-BYO-000040'
  tag fix_id: 'F-62112r929204_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-257088' do
  title 'The EMM system supporting the iOS/iPadOS 16 BYOAD must be configured to detect if known malicious, blocked, or prohibited applications are installed on the BYOAD (DOD-managed segment only).'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and managed data and apps can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure. Detection via collection and analysis of BYOAD-generated logs for noncompliance indicators is acceptable.

This detection capability must be implemented prior to AMD (Approved Mobile Device, called BYOAD device in the STIG) enrollment and AMD access to DOD information and IT resources and continuously monitored on the DOD-managed segment of the AMD enrolled in the program. If non-DOD information (i.e., personal user data, device information) outside the DOD-managed segment of the AMD is required to be accessed, collected, monitored, tracked (i.e., location), or maintained, the circumstances under which this may be done must be outlined in the user agreement.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(3)iii.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify an app vetting process is being used before managed apps are placed in the MDM app repository.

If an app vetting process is not being used before managed apps are placed in the MDM app repository, this is a finding.'
  desc 'fix', 'Implement an app vetting process before managed apps are placed in the MDM app repository.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60773r904007_chk'
  tag severity: 'medium'
  tag gid: 'V-257088'
  tag rid: 'SV-257088r904009_rule'
  tag stig_id: 'AIOS-16-800050'
  tag gtitle: 'PP-BYO-000050'
  tag fix_id: 'F-60714r904008_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

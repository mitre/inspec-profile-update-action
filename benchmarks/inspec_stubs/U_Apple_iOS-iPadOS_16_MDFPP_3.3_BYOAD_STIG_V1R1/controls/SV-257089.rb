control 'SV-257089' do
  title 'The EMM system supporting the iOS/iPadOS 16 BYOAD must be configured to detect if the BYOAD is configured to access nonapproved third-party applications stores (DOD-managed segment only).'
  desc 'DOD policy requires BYOAD devices with DOD data be managed by a DOD MDM server, MAM server, or VMI system. This ensures the device can be monitored for compliance with the approved security baseline and managed data and apps can be removed when the device is out of compliance, which protects DOD data from unauthorized exposure. Detection via collection and analysis of BYOAD-generated logs for noncompliance indicators is acceptable.

This detection capability must be implemented prior to AMD (Approved Mobile Device, called BYOAD device in the STIG) enrollment and AMD access to DOD information and IT resources and continuously monitored on the DOD-managed segment of the AMD enrolled in the program. If non-DOD information (i.e., personal user data, device information) outside the DOD-managed segment of the AMD is required to be accessed, collected, monitored, tracked (i.e., location), or maintained, the circumstances under which this may be done must be outlined in the user agreement.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.a.(3)iii.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Allow Trusting New Enterprise App Authors" is disabled.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify "Allow Trusting New Enterprise App Authors" is disabled.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Trusting enterprise apps not allowed" is listed.

If "Allow Trusting New Enterprise App Authors" is not disabled in the iOS/iPadOS management tool or on the iPhone and iPad, this is a finding.

Note: This requirement is the same as AIOS-16-707000 in the Apple iOS/iPadOS 16 BYOAD STIG.'
  desc 'fix', 'Install a configuration profile to disable "Allow Trusting New Enterprise App Authors".

Note: This requirement is the same as AIOS-16-707000 in the Apple iOS/iPadOS 16 BYOAD STIG.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60774r904010_chk'
  tag severity: 'medium'
  tag gid: 'V-257089'
  tag rid: 'SV-257089r904012_rule'
  tag stig_id: 'AIOS-16-800060'
  tag gtitle: 'PP-BYO-000060'
  tag fix_id: 'F-60715r904011_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-30701' do
  title 'Mobile device software updates must only originate from approved DoD sources.'
  desc 'Users must not accept Over-The-Air (OTA) wireless software updates from the wireless carrier or other non-DoD sources unless the updates have been tested and approved by the ISSO. Unauthorized/unapproved software updates could include malware or cause a degradation of the security posture of the mobile device and DoD network infrastructure. All software updates should be reviewed and/or tested by the mobile device system administrator and originate from a DoD source or DoD-approved source. Mobile device software updates should be pushed from the mobile device management (MDM) server, when this feature is available.'
  desc 'check', 'Detailed Policy Requirements: 
Software updates must come from either DoD sources or DoD-approved sources. Mobile device system administrators should push OTA software updates from the MDM server, when this feature is available. Otherwise the site administrator should verify the non-DoD source of the update has been approved by IT management. 

Check Procedures: 
Interview the ISSO and MDM server system administrator. 

-Verify the site mobile device handheld and MDM server administrators are aware of the requirements. 

-Determine what procedures are used at the site for installing software updates on site-managed mobile devices.

If the site does not have procedures in place, so users can down-load software updates from a DoD source or DoD-approved source, this is a finding.'
  desc 'fix', 'Ensure mobile device software updates originate from DoD sources or approved non-DoD sources only. Users do not accept Over-The-Air (OTA) wireless software updates from non-approved sources.'
  impact 0.3
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-31127r10_chk'
  tag severity: 'low'
  tag gid: 'V-24964'
  tag rid: 'SV-30701r5_rule'
  tag stig_id: 'WIR-SPP-008-02'
  tag gtitle: 'Mobile device provisioning-02'
  tag fix_id: 'F-27598r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end

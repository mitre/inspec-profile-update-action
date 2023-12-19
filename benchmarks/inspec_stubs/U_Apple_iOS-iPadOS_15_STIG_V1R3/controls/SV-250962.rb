control 'SV-250962' do
  title 'Apple iOS/iPadOS 15 users must complete required training.'
  desc "The security posture on iOS devices requires the device user to configure several required policy rules on their device. User Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved users' full access to the Apple App Store, users must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the iOS mobile device and DoD sensitive data may become compromised.

SFR ID: NA"
  desc 'check', 'Review a sample of site User Agreements of iOS device users or similar training records and training course content. Verify iPhone and iPad users have completed required training.

If any iPhone/iPad user has not completed required training, this is a finding.'
  desc 'fix', 'Have all iPhone and iPad users complete training on the following topics. Users must acknowledge receipt of training via a signed User Agreement or similar written record.

Training topics:
- Operational security concerns introduced by unmanaged applications, including applications using global positioning system (GPS) tracking.
- Must ensure no DoD data is saved in an unmanaged app or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DoD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and report any loss of control so the credentials can be revoked. Upon device retirement, turn in, or reassignment, ensure a factory data reset is performed prior to device handoff. Follow mobility service provider decommissioning procedures as applicable. 
- How to configure the following UBE controls (users must configure the control) and other controls on the iPhone and iPad:
**Remove Family Sharing
**Disable Shared Location
**Disable Wi-Fi Assist
**Use AirPrint only with AO-approved printers and print servers (see the Multifunction Device and Network Printers STIG for requirements)
**Turn off "Apps" under "AUTOMATIC DOWNLOADS" in the "iTunes & App Store" section of the Settings app on the iPhone and iPad
**Secure use of Calendar Alarm
**Do not configure a DoD network (work) VPN profile on any third-party unmanaged VPN app 
**Disable iPhone and iPad radios using controls under "Settings" instead of "Control Center"
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.).'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54397r801975_chk'
  tag severity: 'medium'
  tag gid: 'V-250962'
  tag rid: 'SV-250962r801977_rule'
  tag stig_id: 'AIOS-15-011900'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54351r802038_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

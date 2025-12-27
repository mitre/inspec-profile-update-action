control 'SV-257128' do
  title 'Apple iOS/iPadOS 16 users must complete required training.'
  desc "The security posture on iOS devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the authorizing official (AO) has approved users' full access to the Apple App Store, users must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the iOS mobile device and DOD sensitive data may become compromised.

SFR ID: NA"
  desc 'check', 'Review a sample of site User Agreements for iOS device users or similar training records and training course content. Verify iPhone and iPad users have completed required training.

If any iPhone/iPad user has not completed required training, this is a finding.'
  desc 'fix', 'Have all iPhone and iPad users complete training on the following topics. Users must acknowledge receipt of training via a signed User Agreement or similar written record.

Training topics:
- Operational security concerns introduced by unmanaged applications, including applications using global positioning system (GPS) tracking.
- Must ensure no DOD data is saved in an unmanaged app or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DOD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and report any loss of control so the credentials can be revoked. Upon device retirement, turn in, or reassignment, ensure a factory data reset is performed prior to device handoff. Follow mobility service provider decommissioning procedures as applicable. 

For User Enrollment sites:
- How to configure inactivity timeout.
- How to configure force device erase after 10 incorrect password attempts.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60813r904282_chk'
  tag severity: 'medium'
  tag gid: 'V-257128'
  tag rid: 'SV-257128r904284_rule'
  tag stig_id: 'AIOS-16-711900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-60754r904283_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end

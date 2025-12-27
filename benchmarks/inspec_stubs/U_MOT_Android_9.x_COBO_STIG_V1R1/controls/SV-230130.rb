control 'SV-230130' do
  title 'Motorola Android Pie users must complete required training.'
  desc 'The security posture of Google devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the mobile device may become compromised and DoD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements for Motorola device users or similar training records and training course content. 
 
Verify that Motorola device users have completed the required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO. 
 
If any Motorola device user has not completed the required training, this is a finding.'
  desc 'fix', 'Have all Motorola device users complete training on the following topics. Users should acknowledge that they have reviewed training via a signed User Agreement or similar written record. 
 
Training topics: 
 
- Operational security concerns introduced by unmanaged applications/unmanaged personal space, including applications using global positioning system (GPS) tracking. 
- Need to ensure no DoD data is saved to the personal space or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DoD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and to report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure that a factory data reset is performed prior to device handoff. Follow mobility service provider decommissioning procedures as applicable. 
- How to configure the following UBE controls (users must configure the control) on the Motorola device: 
 **Secure use of Calendar Alarm. 
 **Local screen mirroring and Mirroring procedures (authorized/not authorized for use).
 **Do not upload DoD contacts via smart call and caller ID services. 
 **Do not remove DoD intermediate and root PKI digital certificates. 
 **Disable Wi-Fi Sharing. 
 **Do not configure a DoD network (work) VPN profile on any third-party VPN client installed in the personal space.
 **If Bluetooth connections are approved for mobile device, types of allowed connections (for example car hands free but not Bluetooth wireless keyboard).
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Motorola device personal space.

Motorola provides an Administrative Guide for the LEX L11 device to NIAP customers (refer to https://www.niap-ccevs.org/MMO/Product/st_vid11002-agd.pdf). The guide includes procedures for configuring Common Criteria on the Motorola Solutions, Inc. LEX L11 device.'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COBO STIG'
  tag check_id: 'C-32445r538386_chk'
  tag severity: 'medium'
  tag gid: 'V-230130'
  tag rid: 'SV-230130r569707_rule'
  tag stig_id: 'MOTO-09-008700'
  tag gtitle: 'GOOG-09-008700'
  tag fix_id: 'F-32423r538387_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

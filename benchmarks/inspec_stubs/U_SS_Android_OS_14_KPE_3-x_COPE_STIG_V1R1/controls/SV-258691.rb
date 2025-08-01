control 'SV-258691' do
  title 'Samsung Android device users must complete required training.'
  desc 'The security posture of Samsung devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the Samsung mobile device may become compromised, and DOD sensitive data may become compromised.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review a sample of site User Agreements for Samsung device users or similar training records and training course content. 

Verify Samsung device users have completed required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO.

If any Samsung device user has not completed required training, this is a finding.'
  desc 'fix', 'Have all Samsung device users complete training on the following topics. Users should acknowledge they have reviewed training via a signed User Agreement or similar written record.

Training topics:

- Operational security concerns introduced by unmanaged applications/unmanaged personal space including applications using Global Positioning System (GPS) tracking.

- Need to ensure no DOD data is saved to the personal space or transmitted from a personal app (for example, from personal email).

- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DOD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure a factory data reset is performed prior to device hand-off. Follow Mobility service provider decommissioning procedures as applicable. 

- How to configure the following UBE controls (users must configure the control) on the Samsung device:
1. Secure use of Calendar Alarm.
2. Local screen mirroring and MirrorLink procedures (authorized/not authorized for use).
3. Do not connect Samsung devices (via either DeX Station or dongle) to any DOD network via Ethernet connection.
4. Do not upload DOD contacts via smart call and caller ID services.
5. Disable Wi-Fi Sharing.
6. Do not configure a DOD network (work) VPN profile on any third-party VPN client installed in the personal space.

- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Samsung device personal space.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62431r931271_chk'
  tag severity: 'medium'
  tag gid: 'V-258691'
  tag rid: 'SV-258691r931273_rule'
  tag stig_id: 'KNOX-14-210300'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62340r931272_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

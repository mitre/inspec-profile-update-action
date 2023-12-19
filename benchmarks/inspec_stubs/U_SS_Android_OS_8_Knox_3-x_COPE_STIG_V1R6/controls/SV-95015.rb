control 'SV-95015' do
  title 'Samsung Android 8 mobile device users must complete required training.'
  desc 'The security posture of Samsung devices requires the device user to configure several required policy rules on their device. User Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the Samsung mobile device may become compromised and DoD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements of Samsung device users or similar training records and training course content. 

Verify Samsung device users have completed required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO.

If any Samsung device user is found not to have completed required training, this is a finding.'
  desc 'fix', 'Have all Samsung device users complete training on the following topics. Users should acknowledge they have reviewed training via a signed User Agreement or similar written record.

Training topics:

- Operational security concerns introduced by unmanaged applications/unmanaged personal space including applications using global positioning system (GPS) tracking.
- Need to ensure no DoD data is saved to the personal space or transmitted from a personal app (for example, from personal email).
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DoD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and to report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure a factory data reset is performed prior to device hand-off. Follow Mobility service provider decommissioning procedures as applicable. 
- How to configure the following UBE controls (users must configure the control) on the Samsung device:
**Secure use of Calendar Alarm
**Local screen mirroring and MirrorLink procedures (authorized/not authorized for use)
**Disable Report Diagnostic Info and Google Usage & Diagnostics
**Do not connect Samsung DeX Station to any DoD network via Ethernet connection
**Do not upload DoD contacts via smart call and caller ID services
**Do not remove DoD intermediate and root PKI digital certificates
**Disable Wi-Fi Sharing
**Do not configure a DoD network (work) VPN profile on any third-party VPN client installed in the personal space
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Samsung device personal space.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80311'
  tag rid: 'SV-95015r1_rule'
  tag stig_id: 'KNOX-08-008100'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87117r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

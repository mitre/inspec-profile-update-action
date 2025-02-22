control 'SV-91323' do
  title 'Samsung Android 7 mobile device users must complete required training.'
  desc 'The security posture of Samsung devices requires the device user to configure several required policy rules on their device. User Based Enforcement (UBE) is required for these controls. In addition, if the AO has approved the use of an unmanaged personal container, than the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the Samsung mobile device may become compromised and DoD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements of Samsung device users or similar training records and training course content. Verify Samsung device users have completed required training.

Any Samsung device user is found to not have completed required training, this is a finding.'
  desc 'fix', 'Have all Samsung device users complete training on the following topics. Users should acknowledge they have received training via a signed User Agreement or similar written record.

Training Topics:

- Operational security concerns introduced by unmanaged applications/unmanaged personal space/container including applications utilizing global positioning system (GPS) tracking
- Need to ensure no DoD data is saved to the personal container or transmitted from a personal app (for example, from personal email) 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DoD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys, and to report any loss of control so that the credentials can be revoked. Upon device retirement, turn in, or reassignment, ensure a factory data reset is performed prior to device hand off. Follow Mobility service provider decommissioning procedures as applicable. 
- How to configure the following User Based Enforcement (UBE) controls (users must configure the control) on the Samsung device:
- secure use of Calendar Alarm
- local screen mirroring and MirrorLink procedures (authorized/not authorized for use)
- disable Report Diagnostic Info
- do not connect Samsung DeX Station to any DoD network via Ethernet connection
- disable Phone Visibility
- disable Smart Call
- disable Nearby device scanning
- do not remove DoD intermediate and root PKI digital certificates
- disable WiFi Sharing
- do not configure a DoD network (work) VPN profile on any third-party VPN client installed in the personal space/container 
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Samsung device personal space/container.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76627'
  tag rid: 'SV-91323r1_rule'
  tag stig_id: 'KNOX-07-019000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83321r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

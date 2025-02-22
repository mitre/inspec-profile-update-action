control 'SV-235082' do
  title 'Honeywell Mobility Edge Android Pie devices users must complete required training.'
  desc 'The security posture of Honeywell devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the Honeywell mobile device may become compromised and DoD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements for Honeywell device users or similar training records and training course content. 
 
Verify that Honeywell device users have completed the required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO. 
 
If any Honeywell device user has not completed the required training, this is a finding.'
  desc 'fix', 'Have all Honeywell device users complete training on the following topics. Users should acknowledge that they have reviewed training via a signed User Agreement or similar written record. 
 
Training topics: 
 
- Operational security concerns introduced by unmanaged applications/unmanaged personal space, including applications using global positioning system (GPS) tracking. 
- Need to ensure no DoD data is saved to the personal space or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DoD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and to report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure that a factory data reset is performed prior to device hand-off. Follow mobility service provider decommissioning procedures as applicable. 
- How to configure the following UBE controls (users must configure the control) on the Honeywell device: 
 **Secure use of Calendar Alarm 
 **Local screen mirroring and Mirroring procedures (authorized/not authorized for use) 
 **Do not upload DoD contacts via smart call and caller ID services 
 **Do not remove DoD intermediate and root PKI digital certificates 
 **Disable Wi-Fi Sharing 
 **Do not configure a DoD network (work) VPN profile on any third-party VPN client installed in the personal space 
 **If Bluetooth connections are approved for mobile device, types of allowed connections (for example car handsfree, but not Bluetooth wireless keyboard)
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Honeywell device personal space.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38301r623261_chk'
  tag severity: 'medium'
  tag gid: 'V-235082'
  tag rid: 'SV-235082r626527_rule'
  tag stig_id: 'HONW-09-008700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38264r623262_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

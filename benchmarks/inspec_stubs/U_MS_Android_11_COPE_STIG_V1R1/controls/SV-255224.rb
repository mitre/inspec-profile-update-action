control 'SV-255224' do
  title 'Microsoft Android 11 users must complete required training.'
  desc 'The security posture of Android devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the mobile device may become compromised and DOD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements for Microsoft device users or similar training records and training course content. 
 
Verify that Microsoft device users have completed the required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO. 
 
If any Microsoft device user has not completed the required training, this is a finding.'
  desc 'fix', 'All Microsoft device users must complete training on the following training topics. (Users must acknowledge that they have reviewed training via a signed User Agreement or similar written record): 
 
- Operational security concerns introduced by unmanaged applications/unmanaged personal space (personal profile), including applications using global positioning system (GPS) tracking. 
- Need to ensure no DOD data is saved to the personal space or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for maintaining positive control of their credentialed device at all times. The DOD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and to report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure that a factory data reset is performed prior to device hand-off. Follow mobility service provider decommissioning procedures as applicable.
- How to configure the following UBE controls (users must configure the control) on the Google device: 
  **Secure use of Calendar Alarm.
  **Local screen mirroring and Mirroring procedures (authorized/not authorized for use).
  **Do not upload DOD contacts via smart call and caller ID services.
  **Do not remove DOD intermediate and root PKI digital certificates. 
  **Disable Wi-Fi Sharing. 
  **Do not configure a DOD network (work) VPN profile on any third-party VPN client installed in the personal space. 
  **If Bluetooth connections are approved for mobile device, types of allowed connections (for example car hands-free, but not Bluetooth wireless keyboard).
- AO guidance on acceptable use and restrictions, if any, on downloading and installing personal apps and data (music, photos, etc.) in the Google device personal space.'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58837r869287_chk'
  tag severity: 'medium'
  tag gid: 'V-255224'
  tag rid: 'SV-255224r870836_rule'
  tag stig_id: 'MSFT-11-008700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-58781r869288_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

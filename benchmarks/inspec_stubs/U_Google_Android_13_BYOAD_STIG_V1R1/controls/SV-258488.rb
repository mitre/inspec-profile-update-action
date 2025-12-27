control 'SV-258488' do
  title 'Google Android 13 users must complete required training.'
  desc 'The security posture of Google devices requires the device user to configure several required policy rules on their device. User-Based Enforcement (UBE) is required for these controls. In addition, if the Authorizing Official (AO) has approved the use of an unmanaged personal space, the user must receive training on risks. If a user is not aware of their responsibilities and does not comply with UBE requirements, the security posture of the Google mobile device and DOD sensitive data may become compromised.

SFR ID: NA'
  desc 'check', 'Review a sample of site User Agreements for Google Android 13 device users or similar training records and training course content. 
 
Verify the Google Android 13 device users have completed the required training. The intent is that required training is renewed on a periodic basis in a time period determined by the AO. 
 
If any Google Android 13 device user has not completed the required training, this is a finding.'
  desc 'fix', 'All Google Android 13 device users must complete training on the following training topics (users must acknowledge that they have reviewed training via a signed User Agreement or similar written record): 
- Operational security concerns introduced by unmanaged applications/unmanaged personal space, including applications using global positioning system (GPS) tracking.
- The need to ensure no DOD data is saved to the personal space or transmitted from a personal app (for example, from personal email). 
- If the Purebred key management app is used, users are responsible for always maintaining positive control of their credentialed device. The DOD PKI certificate policy requires subscribers to maintain positive control of the devices that contain private keys and to report any loss of control so the credentials can be revoked. Upon device retirement, turn-in, or reassignment, ensure that a factory data reset is performed prior to device hand-off. Follow mobility service provider decommissioning procedures as applicable.
- How to configure the following UBE controls (users must configure the control) on the Google device: 
 **Do not remove DOD intermediate and root PKI digital certificates 
 **Do not configure a DOD network (work) VPN profile on any third-party VPN client installed in the personal space 
- How to implement OneLock.
- Screenshots will not be taken of any “work” related managed data.-Screenshots will not be taken of any “work” related managed data.'
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62228r929278_chk'
  tag severity: 'medium'
  tag gid: 'V-258488'
  tag rid: 'SV-258488r929280_rule'
  tag stig_id: 'GOOG-13-709800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62137r929279_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

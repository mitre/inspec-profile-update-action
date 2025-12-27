control 'SV-8783' do
  title 'A policy/SOP is NOT in place OR NOT enforced to ensure that the VVoIP terminal (VoIP phone or instrument) configuration and display password/PIN is managed IAW DOD password policies (e.g., password/PIN complexity (length and character mix), expiration, change intervals, other conditions requiring a change, reuse, protection and storage).'
  desc 'Per other requirements, the network configuration information and settings on a VoIP instrument must be protected by a password or PIN. VVoIP endpoints do not typically provide automated PIN/password management. PINs that are not managed or required to be changed are most likely never changed, therefore they are easily compromised or guessed. Additionally as SA personnel change, the group passwords and PINs they know and use must be changed. As such, the organization must have and follow a policy and procedure for managing the passwords or PINs used to access the local VoIP phone network configurations. Such a SOP should address password/PIN complexity (length and character mix), expiration, change intervals, other conditions requiring a change, reuse, protection and storage. NOTE: Most instruments will only accept numerical input therefore a PIN is used. Some instruments may accept alpha characters for passwords. These factors help determine the password/PIN complexity that is achievable.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:  Ensure that a policy/SOP is in place and enforced to ensure that the IPT terminal (VoIP phone or instrument) configuration and display password/PIN is managed IAW DOD password policies (e.g., password/PIN complexity (length and character mix), expiration, change intervals, other conditions requiring a change, reuse, protection and storage).

Additionally investigate the enforcement of the SOP.

This is a finding in the event there is no SOP addressing the concern here or the SOP does not adequately address the related DoD policies OR the policy/SOP is not enforced.'
  desc 'fix', 'Ensure that a policy/SOP is in place and enforced to ensure that the IPT terminal (VoIP phone or instrument) configuration and display password/PIN is managed IAW DOD password policies (e.g., password/PIN complexity (length and character mix), expiration, change intervals, other conditions requiring a change, reuse, protection and storage).

Develop a policy/SOP and enforced it to ensure that the IPT terminal (VoIP phone or instrument) configuration and display password is managed IAW DOD password policies (e.g., password/PIN complexity (length and character mix), expiration, change intervals, other conditions requiring a change, reuse, protection and storage)).'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23600r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8288'
  tag rid: 'SV-8783r1_rule'
  tag stig_id: 'VVoIP 1500 (GENERAL)'
  tag gtitle: 'Deficient SOP: endpt netwk config PIN/pswd mgmt'
  tag fix_id: 'F-20116r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Denial of Service and/or unauthorized access to network or voice system resources or services and the information they contain. Loss of confidentiality.
Password or PIN code compromise. As compromise is easier or more likely if PINs are not managed.'
  tag responsibility: 'Information Assurance Officer'
end

control 'SV-84333' do
  title 'Windows 10 Mobile must not allow use of developer modes.'
  desc 'Developer modes expose features of the MOS that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD-sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #24'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. 

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for restricting the Developer Unlocking/Developer Mode capability.
3. Verify that setting is set to disabled/off.

On the Windows 10 Mobile device:

1. Launch "Settings".
2. Tap on "Update & security" and then tap on "For developers".
3. Verify that the setting titled "Developer mode" is not selected and it is disabled/read-only.

If the MDM does not have the Developer Unlocking/Developer Mode policy to disable developer mode enforced, or if on the phone the setting titled "Developer mode" is not disabled/read-only on the "Developer mode" screen, this is a finding.'
  desc 'fix', 'Configure the MDM system to require the Developer Unlocking/Developer Mode policy be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70153r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69711'
  tag rid: 'SV-84333r1_rule'
  tag stig_id: 'MSWM-10-200303'
  tag gtitle: 'PP-MDF-201010'
  tag fix_id: 'F-75915r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

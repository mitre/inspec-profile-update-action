control 'SV-84733' do
  title 'Windows 10 Mobile must be configured to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor (e.g., using a fingerprint), unless mechanism is DoD-approved.'
  desc 'The fingerprint reader or iris scan (supported by some Windows 10 Mobile devices) can be used to authenticate the user in order to unlock the mobile device. At this time, no biometric reader has been approved for DoD use on mobile devices. This technology would allow unauthorized users to have access to DoD sensitive data if compromised. By not permitting the use of non-password authentication mechanisms, users are forced to use passcodes that meet DoD passcode requirements.

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', 'Review Windows 10 Mobile documentation and inspect the configuration on Windows 10 Mobile to disable authentication mechanisms providing user access to protected data other than a Password Authentication Factor (e.g., using a fingerprint), unless mechanism is DoD-approved.

This validation procedure is performed only on the MDM administration console.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for restricting Biometrics authentication "Biometrics/UseBiometrics".
3. Verify that setting restriction is turned on (feature disabled).

If the MDM does not have a compliance policy that disables "Biometrics/UseBiometrics", this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "Biometrics/UseBiometrics" policy to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70111'
  tag rid: 'SV-84733r1_rule'
  tag stig_id: 'MSWM-10-202801'
  tag gtitle: 'PP-MDF-201028'
  tag fix_id: 'F-76347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

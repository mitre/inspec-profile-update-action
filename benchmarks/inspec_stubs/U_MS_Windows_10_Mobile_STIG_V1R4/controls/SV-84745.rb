control 'SV-84745' do
  title 'Windows 10 Mobile must be configured to implement the management setting: Disable the ability for a user to add new email accounts.'
  desc 'Personal or unauthorized email accounts can lead to the transmission of sensitive DoD data to unauthorized recipients Disabling this feature mitigates the risk. The use of personal or non-DoD email accounts on a DoD mobile device should be approved by the Authorizing Official (AO).

SFR ID: FMT_SMF_EXT.1.1 #45'
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if the mobile device is enforcing the policy to prevent additional email accounts from being added by a user. If feasible, use a spare device to attempt to add a new email account.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device. 

Check whether the appropriate setting is configured on the MDM.

Administration Console:

Ask the MDM administrator to verify the "allow adding non-Microsoft e-mail accounts" security policy was set to be disallowed for Windows 10 Mobile devices.

On the Windows 10 Mobile device:

1. Go to "settings".
2. Navigate to "Accounts", then under Email, calendar, and contacts tap on "Email & app accounts".
3. Tap the "+ Add an account" button.
4. Verify that a screen comes up and says "Can't create account - Your company won't allow you to create that type of account".

If the MDM does not disable the policy for setting for "allow adding non-Microsoft email accounts" or if on the phone a message starting with the sentence "Can't create account - Your company won't allow you to create that type of account" is not shown when tapping on the "+ Add an account" button in the "Email & app accounts" app, this is a finding.)
  desc 'fix', 'Configure the MDM system to enforce a policy that restricts the "allow adding non-Microsoft email accounts" policy to prevent users from being able to add new email accounts. 

Deploy the policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70123'
  tag rid: 'SV-84745r1_rule'
  tag stig_id: 'MSWM-10-910201'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-76359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

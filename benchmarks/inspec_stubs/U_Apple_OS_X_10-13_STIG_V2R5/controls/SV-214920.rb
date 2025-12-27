control 'SV-214920' do
  title 'The macOS system must enforce an account lockout time period of 15 minutes in which a user makes three consecutive invalid logon attempts.'
  desc 'Setting a lockout time period of 15 minutes is an effective deterrent against brute forcing that also makes allowances for legitimate mistakes by users. When three invalid logon attempts are made, the account will be locked.'
  desc 'check', 'Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following command to check if the system has the correct setting for the logon reset timer:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep minutesUntilFailedLoginReset

If the return is null or not “minutesUntilFailedLoginReset = 15”, this is a finding.

If password policy is set with the "pwpolicy" utility, the variable names may vary depending on how the policy was set. To check if the password policy is configured to disable an account for 15 minutes after 3 unsuccessful logon attempts, run the following command to output the password policy to the screen:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies

Look for the line "<key>policyCategoryAuthentication</key>".

If this does not exist, and password policy is not controlled by a directory service, this is a finding.

In the array that follows, there should be one or more <dict> sections that describe policy checks. One should contain a <string> that allows users to log on if "policyAttributeFailedAuthentications" is less than "policyAttributeMaximumFailedAuthentications". Under policyParameters, "policyAttributeMaximumFailedAuthentications" should be set to "3".

If "policyAttributeMaximumFailedAuthentications" is not set to "3", this is a finding.

In the same check or in another <dict> section, there should be a <string> that allows users to log on if the "policyAttributeCurrentTime" is greater than the result of adding "15" minutes (900 seconds) to "policyAttributeLastFailedAuthenticationTime". The check might use a variable defined in its "policyParameters" section.

If the check does not exist or if the check adds too great an amount of time, this is a finding.'
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.

The following two lines within the configuration enforce lockout expiration to "15" minutes:

<key>autoEnableInSeconds</key>
<integer>900</integer>

To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the generated file in a text editor and ensure it contains the following text after the opening <dict> tag and before the closing </dict> tag.

Replace <dict/> first with <dict></dict> if necessary.

<key>policyCategoryAuthentication</key>
<array>
<dict>
<key>policyContent</key>
<string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
<key>policyIdentifier</key>
<string>Authentication Lockout</string>
<key>policyParameters</key>
<dict>
<key>autoEnableInSeconds</key>
<integer>900</integer>
<key>policyAttributeMaximumFailedAuthentications</key>
<integer>3</integer>
</dict>
</dict>
</array>

If the line "<key>policyCategoryAuthentication</key>" already exists, the following text should be used instead and inserted after the first <array> tag that follows it:

<dict>
<key>policyContent</key>
<string>(policyAttributeFailedAuthentications < policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime > (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
<key>policyIdentifier</key>
<string>Authentication Lockout</string>
<key>policyParameters</key>
<dict>
<key>autoEnableInSeconds</key>
<integer>900</integer>
<key>policyAttributeMaximumFailedAuthentications</key>
<integer>3</integer>
</dict>
</dict>

After saving the file and exiting to the command prompt, run the following command to load the new policy file:

/usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist

Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user creation operations, as well as lock out all local users, including administrators.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16120r397332_chk'
  tag severity: 'medium'
  tag gid: 'V-214920'
  tag rid: 'SV-214920r609363_rule'
  tag stig_id: 'AOSX-13-001324'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-16118r397333_fix'
  tag 'documentable'
  tag legacy: ['V-81721', 'SV-96435']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end

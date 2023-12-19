control 'SV-90763' do
  title 'The OS X system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following command to check if the system is configured to require that passwords contain at least one numeric character:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep requireAlphanumeric

If "requireAlphanumeric" is not set to "1" or is undefined, this is a finding.

If password policy is set with the "pwpolicy utility", run the following command instead:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies

Look for the line "<key>policyCategoryPasswordContent</key>".

If it does not exist, and password policy is not controlled by a directory service, this is a finding.

Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> that "matches" the variable "policyAttributePassword" to the regular expression "(.*[0-9].*){1,}+" or to a similar expression that will ensure the password contains a character in the range 0-9 one or more times.

If this check allows users to create passwords without at least one numeric character, or if no such check exists, this is a finding.'
  desc 'fix', %q(This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.

To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the generated file in a text editor.

If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>; then insert the following text after the opening <dict> tag and before the closing </dict> tag.

The same text can also be used if the line "<key>policyCategoryPasswordContent</key>" is not present.

<key>policyCategoryPasswordContent</key>
<array>
<dict>
<key>policyContent</key>
<string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
<key>policyIdentifier</key>
<string>com.apple.policy.legacy.requiresNumeric</string>
<key>policyParameters</key>
<dict>
<key>minimumNumericCharacters</key>
<integer>1</integer>
</dict>
</dict>
</array>

If the file does contain policy settings, and the line "<key>policyCategoryPasswordContent</key>" does exist, insert the following text after the opening <array> tag that comes right after it:

<dict>
<key>policyContent</key>
<string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
<key>policyIdentifier</key>
<string>com.apple.policy.legacy.requiresNumeric</string>
<key>policyParameters</key>
<dict>
<key>minimumNumericCharacters</key>
<integer>1</integer>
</dict>
</dict>

After saving the file and exiting to the command prompt, run the following command to load the new policy file:

/usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist

Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user creation operations, as well as lock out all local users, including administrators.)
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76075'
  tag rid: 'SV-90763r1_rule'
  tag stig_id: 'AOSX-12-000585'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-82713r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end

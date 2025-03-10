control 'SV-214927' do
  title 'The macOS system must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically.

One method of minimizing this risk is to use complex passwords and periodically change them. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', 'Password policy can be set with a configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following command to check if the system is configured to require users to change their passwords every 60 days:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep maxPINAgeInDays
If the return is null, or is not “maxPINAgeInDays = 60” or set to a smaller value, this is a finding.

If password policy is set with the "pwpolicy" utility, run the following command instead:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies

Look for the line <key>policyCategoryPasswordChange</key>.

If it does not exist, and password policy is not controlled by a directory service, this is a finding.

Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> that compares the variable "policyAttributeLastPasswordChangeTime" to the variable "policyAttributeCurrentTime". It may contain additional variables defined in the "policyParameters" section that follows it. All comparisons are done in seconds.

If this check allows users to log in with passwords older than "60" days, or if no such check exists, this is a finding.'
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.

To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the generated file in a text editor.

If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>.

If there already is a policy block that refers to password expiration, ensure it is set to "60" days.

If the line "<key>policyCategoryPasswordChange</key>" is not present in the file, add the following text immediately after the opening <dict> tag in the file:

<key>policyCategoryPasswordChange</key>
<array>
<dict>
<key>policyContent</key>
<string>policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
<key>policyIdentifier</key>
<string>Password Change Interval</string>
<key>policyParameters</key>
<dict>
<key>policyAttributeExpiresEveryNDays</key>
<integer>60</integer>
</dict>
</dict>
</array>

If the line "<key>policyCategoryPasswordChange</key>" is already present in the file, the following text should be added just after the opening <array> tag that follows the line instead:

<dict>
<key>policyContent</key>
<string>policyAttributeCurrentTime > policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
<key>policyIdentifier</key>
<string>Password Change Interval</string>
<key>policyParameters</key>
<dict>
<key>policyAttributeExpiresEveryNDays</key>
<integer>60</integer>
</dict>
</dict>

After saving the file and exiting to the command prompt, run the following command to load the new policy file:

/usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist

Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user creation operations, as well as lock out all local users, including administrators.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16127r397353_chk'
  tag severity: 'medium'
  tag gid: 'V-214927'
  tag rid: 'SV-214927r609363_rule'
  tag stig_id: 'AOSX-13-002085'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-16125r397354_fix'
  tag 'documentable'
  tag legacy: ['V-81735', 'SV-96449']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

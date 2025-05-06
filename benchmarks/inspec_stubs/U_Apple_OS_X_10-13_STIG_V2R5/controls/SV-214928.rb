control 'SV-214928' do
  title 'The macOS system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Password policy can be set with the "Password Policy" configuration profile or the "pwpolicy" utility. If password policy is set with a configuration profile, run the following command to check if the system is configured to require that users cannot reuse one of their five previously used passwords:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep pinHistory

If the return in null or not “pinHistory = 5” or greater, this is a finding.

If password policy is set with the "pwpolicy" utility, run the following command instead:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies

Look for the line "<key>policyCategoryPasswordContent</key>".

If it does not exist, and password policy is not controlled by a directory service, this is a finding.

Otherwise, in the array section that follows it, there should be a <dict> section that contains a check <string> such as "<string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>". This searches for the hash of the user-entered password in the list of previous password hashes. In the "policyParameters" section that follows it, "policyAttributePasswordHistoryDepth" must be set to "5" or greater.

If this parameter is not set to "5" or greater, or if no such check exists, this is a finding.'
  desc 'fix', 'This setting may be enforced using the "Passcode Policy" configuration profile or by a directory service.

To set the password policy without a configuration profile, run the following command to save a copy of the current "pwpolicy" account policy file:

/usr/bin/sudo /usr/bin/pwpolicy getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the generated file in a text editor. If the file does not yet contain any policy settings, replace <dict/> with <dict></dict>. If there already is a policy block that refers to password history, ensure it is set to "5". If the line "<key>policyCategoryPasswordContent</key>" is not present in the file, add the following text immediately after the opening <dict> tag in the file:

<key>policyCategoryPasswordContent</key>
<array>
<dict>
<key>policyContent</key>
<string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
<key>policyIdentifier</key>
<string>Password History</string>
<key>policyParameters</key>
<dict>
<key>policyAttributePasswordHistoryDepth</key>
<integer>5</integer>
</dict>
</dict>
</array>

If the line "<key>policyCategoryPasswordContent</key>" is already present in the file, the following text should be added just after the opening <array> tag that follows the line instead:

<dict>
<key>policyContent</key>
<string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
<key>policyIdentifier</key>
<string>Password History</string>
<key>policyParameters</key>
<dict>
<key>policyAttributePasswordHistoryDepth</key>
<integer>5</integer>
</dict>
</dict>

After saving the file and exiting to the command prompt, run the following command to load the new policy file:

/usr/bin/sudo /usr/bin/pwpolicy setaccountpolicies pwpolicy.plist

Note: Updates to password restrictions must be thoroughly evaluated in a test environment. Mistakes in configuration may block password change and local user creation operations, as well as lock out all local users, including administrators.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16128r397356_chk'
  tag severity: 'medium'
  tag gid: 'V-214928'
  tag rid: 'SV-214928r609363_rule'
  tag stig_id: 'AOSX-13-002090'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-16126r397357_fix'
  tag 'documentable'
  tag legacy: ['SV-96451', 'V-81737']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

control 'SV-214820' do
  title 'The macOS system must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by attackers to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify if a password policy is enforced by a directory service by asking the System Administrator (SA) or Information System Security Officer (ISSO). 

If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the policy was set. 

To check if the password policy is configured to disable a temporary account after 72 hours, run the following command to output the password policy to the screen, substituting the correct user name in place of username:

/usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2

If there is no output, and password policy is not controlled by a directory service, this is a finding.

Otherwise, look for the line "<key>policyCategoryAuthentication</key>".

In the array that follows, there should be a <dict> section that contains a check <string> that allows users to log in if "policyAttributeCurrentTime" is less than the result of adding "policyAttributeCreationTime" to 72 hours (259299 seconds). The check might use a variable defined in its "policyParameters" section.

If the check does not exist or if the check adds too great an amount of time to "policyAttributeCreationTime", this is a finding.'
  desc 'fix', 'This setting may be enforced using a configuration profile or by a directory service.

To set the password policy without a configuration profile, run the following command to save a copy of the current policy file, substituting the correct user name in place of "username":

/usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the resulting password policy file in a text editor.

If other policy settings are present, and the line "<key>policyCategoryAuthentication</key>" already exists, insert the following text after the <array> tag that immediately follows it:

<dict>
<key>policyContent</key>
<string>policyAttributeCurrentTime < policyAttributeCreationTime + 259299</string>
<key>policyIdentifier</key>
<string>Disable Temporary Account</string>
</dict>

At a minimum, edit the file to ensure that it contains the following text:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>policyCategoryAuthentication</key>
<array>
<dict>
<key>policyContent</key>
<string>policyAttributeCurrentTime < policyAttributeCreationTime + 259299</string>
<key>policyIdentifier</key>
<string>Disable Temporary Account</string>
</dict>
</array>
</dict>
</plist>

After saving the file and exiting to the command prompt, run the following command to load the new policy file, substituting the correct user name in place of "username":

/usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies pwpolicy.plist'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16020r397032_chk'
  tag severity: 'medium'
  tag gid: 'V-214820'
  tag rid: 'SV-214820r609363_rule'
  tag stig_id: 'AOSX-13-000110'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-16018r397033_fix'
  tag 'documentable'
  tag legacy: ['SV-96215', 'V-81501']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end

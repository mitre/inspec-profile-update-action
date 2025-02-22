control 'SV-257150' do
  title 'The macOS system must automatically remove or disable temporary and emergency user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by attackers to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DOD-defined time period of 72 hours.

Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency administrator account is normally a different account created for use by vendors or system maintainers.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Verify the macOS system is configured with a policy via directory service to disable temporary or emergency accounts after 72 hours by asking the System Administrator (SA) or Information System Security Officer (ISSO).

If a policy is not set by a directory service, a password policy must be set with the "pwpolicy" utility. The variable names may differ depending on how the policy was set.

If temporary or emergency accounts are not defined on the macOS system, this is not applicable.

Verify the macOS system is configured with a policy to disable temporary or emergency accounts after 72 hours with the following command:

/usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2

If there is no output and password policy is not controlled by a directory service, this is a finding.

Otherwise, look for the line "<key>policyCategoryAuthentication</key>".

In the array that follows, a <dict> section contains a check <string> that allows users to log in if "policyAttributeCurrentTime" is less than the result of adding "policyAttributeCreationTime" to 72 hours (259299 seconds). The check might use a variable defined in its "policyParameters" section.

If the check does not exist or if the check adds more than 72 hours to "policyAttributeCreationTime", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable temporary or emergency accounts after 72 hours. This setting may be enforced using local policy or by a directory service.

To set local policy to disable a temporary or emergency user, create a plain text file containing the following:

   <dict>
     <key>policyCategoryAuthentication</key>
     <array>
       <dict>
         <key>policyContent</key>
         <string>policyAttributeCurrentTime &lt; policyAttributeCreationTime+259299</string>
         <key>policyIdentifier</key>
         <string>Disable Tmp Accounts </string>
       </dict>
     </array>
   </dict>

After saving the file and exiting to the command prompt, run the following command to load the new policy file, substituting the correct user name in place of "username" and the path to the file in place of "/path/to/file".

/usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies /path/to/file'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60835r905081_chk'
  tag severity: 'medium'
  tag gid: 'V-257150'
  tag rid: 'SV-257150r905083_rule'
  tag stig_id: 'APPL-13-000012'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-60776r905082_fix'
  tag satisfies: ['SRG-OS-000002-GPOS-00002', 'SRG-OS-000123-GPOS-00064']
  tag 'documentable'
  tag cci: ['CCI-000016', 'CCI-001682']
  tag nist: ['AC-2 (2)', 'AC-2 (2)']
end

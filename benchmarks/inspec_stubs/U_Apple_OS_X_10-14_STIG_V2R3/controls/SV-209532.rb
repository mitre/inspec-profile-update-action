control 'SV-209532' do
  title 'The macOS system must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours.'
  desc 'Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency administrator account is normally a different account created for use by vendors or system maintainers.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'If an emergency account has been created on the system, check the expiration settings of a local account using the following command, replacing "username" with the correct value:

/usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2

If there is output, verify that the account policies do not restrict the ability to log in after a certain date or amount of time.

If they do, this is a finding.'
  desc 'fix', %q(To remove all "pwpolicy" settings for an emergency account, run the following command, replacing "username" with the correct value:

/usr/bin/sudo /usr/bin/pwpolicy -u username clearaccountpolicies

Otherwise, to change the passcode policy for an emergency account and only remove some policy sections, run the following command to save a copy of the current policy file for the specified username:

/usr/bin/sudo /usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2 > pwpolicy.plist

Open the resulting passcode policy file in a text editor and remove any policyContent sections that would restrict the ability to log in after a certain date or amount of time.

To remove the section cleanly, remove the entire text that begins with <dict>, contains <key>policyContent<'/key>, and ends with </dict>.

After saving the file and exiting to the command prompt, run the following command to load the new policy file:

/usr/bin/sudo /usr/bin/pwpolicy -u username setaccountpolicies pwpolicy.plist)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9783r466282_chk'
  tag severity: 'medium'
  tag gid: 'V-209532'
  tag rid: 'SV-209532r610285_rule'
  tag stig_id: 'AOSX-14-000013'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-9783r466283_fix'
  tag 'documentable'
  tag legacy: ['V-95807', 'SV-104945']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end

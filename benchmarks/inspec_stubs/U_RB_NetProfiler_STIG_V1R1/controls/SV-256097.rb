control 'SV-256097' do
  title 'The network device must terminate shared/group account credentials when members leave the group.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. 

There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.

The “mazu” account is the local Linux OS account created and used by the NetProfiler and Flow Gateway application for ownership of application, configuration, and data files stored on the appliance. Operations such as changing appliance settings and running reports on a cluster, as well as using backup/restore functionality rely on the existence of the “mazu” user. The account is required for proper operation of the solution. However, the ability to login to this account can be disabled on the Security Compliance page, as well as firewall rules can be used to restrict the remote access.'
  desc 'check', "Review the site's System Security Plan (SSP) to verify the password for the account of last resort and/or the root account are changed when a system administrator with knowledge of the password leaves or no longer has a need to know/access.

If the credentials for the account of last resort are not changed when administrators who know the credential leave the organization, this is a finding."
  desc 'fix', 'Change the account of last resort to a new password when administrators who know the credential leave the organization. Document this process in the SSP.

Set the password for the account of last resort and/or root as needed based on what the person departing had access to.

Change default system shell account passwords as required:

Go to Configuration >> Appliance Security >> Security Compliance page Accounts section to change or disable the following passwords.

root - Accessible only through SSH from other modules in an Enterprise NetProfiler. This has shell access from the console if login is enabled. Change to implement a DOD-compliant password. Securely store and protect the password.

admin - Accessible only through the console port. This is for initial setup only with no shell access. Recommend use as account of last resort; however, login may be disabled only if another account of last resort is configured. Change to implement a DOD-compliant password. Securely store and protect the password. The following system account must be configured to comply with this requirement.

mazu - Accessible through SSH; this has shell access unless disabled. Disable the password (DOD preferred) or change to implement a DOD-compliant password. Securely store and protect the password.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59771r882797_chk'
  tag severity: 'medium'
  tag gid: 'V-256097'
  tag rid: 'SV-256097r882799_rule'
  tag stig_id: 'RINP-DM-000091'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-59714r882798_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end

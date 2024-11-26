control 'SV-253946' do
  title 'The Juniper EX switch must change credentials for account of last resort when administrators who know the credential leave the organization.'
  desc 'A shared/group account credential is a shared form of authentication that allows multiple individuals to access the network device using a single account. If shared/group account credentials are not terminated when individuals leave the group, the user that left the group can still gain access even though they are no longer authorized. There may also be instances when specific user actions need to be performed on the network device without unique administrator identification or authentication. Examples of credentials include passwords and group membership certificates.'
  desc 'check', "Review the site's SSP to verify the password for the account of last resort and the root account are changed when a system administrator with knowledge of the password leaves or no longer has a need to know/access.

If the credentials for account of last resort are not changed when administrators who know the credential leave the organization, this is a finding."
  desc 'fix', 'Document this process in the SSP. Change the account of last resort to a new password when administrators who know the credential leave the organization

Set the password for the account of last resort:
set system login user <account of last resort name> authentication plain-text-password
New password: <password - not echoed to the screen>
Retype new password: <password verification - not echoed to the screen>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57398r843869_chk'
  tag severity: 'medium'
  tag gid: 'V-253946'
  tag rid: 'SV-253946r879694_rule'
  tag stig_id: 'JUEX-NM-000910'
  tag gtitle: 'SRG-APP-000317-NDM-000282'
  tag fix_id: 'F-57349r843870_fix'
  tag 'documentable'
  tag cci: ['CCI-002142']
  tag nist: ['AC-2 (10)']
end

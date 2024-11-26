control 'SV-217267' do
  title 'The SUSE operating system must deny direct logons to the root account using remote access via SSH.'
  desc 'To assure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the UNIX and Windows SUSE operating systems offer a "switch user" capability, allowing users to authenticate with their individual credentials and, when needed, "switch" to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the SUSE operating system without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.'
  desc 'check', 'Verify the SUSE operating system denies direct logons to the root account using remote access via SSH.

Check that SSH denies any user trying to log on directly as root with the following command:

# sudo grep -i permitrootlogin /etc/ssh/sshd_config
PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to deny direct logons to the root account using remote access via SSH.

Edit the appropriate "/etc/ssh/sshd_config" file, add or uncomment the line for "PermitRootLogin" and set its value to "no" (this file may be named differently or be in a different location):

PermitRootLogin no'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18495r369957_chk'
  tag severity: 'medium'
  tag gid: 'V-217267'
  tag rid: 'SV-217267r603262_rule'
  tag stig_id: 'SLES-12-030140'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-18493r369958_fix'
  tag 'documentable'
  tag legacy: ['SV-92145', 'V-77449']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end

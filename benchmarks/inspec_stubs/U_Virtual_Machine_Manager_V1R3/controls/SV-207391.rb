control 'SV-207391' do
  title 'The VMM must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc %q(To assure individual accountability and prevent unauthorized access, organizational users shall be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "Root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the UNIX and Windows VMMs offer a 'switch user' capability allowing users to authenticate with their individual credentials and, when needed, 'switch' to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization which outlines specific user actions that can be performed on the VMM without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.)
  desc 'check', 'Verify the VMM requires individuals to be authenticated with an individual authenticator prior to using a group authenticator.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7648r365583_chk'
  tag severity: 'medium'
  tag gid: 'V-207391'
  tag rid: 'SV-207391r378862_rule'
  tag stig_id: 'SRG-OS-000109-VMM-000550'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-7648r365584_fix'
  tag 'documentable'
  tag legacy: ['SV-71243', 'V-56983']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end

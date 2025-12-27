control 'SV-71023' do
  title 'The operating system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  desc %q(To assure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the UNIX and Windows operating systems offer a 'switch user' capability allowing users to authenticate with their individual credentials and, when needed, 'switch' to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the operating system without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.)
  desc 'check', 'Verify the operating system requires individuals to be authenticated with an individual authenticator prior to using a group authenticator. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require individuals to be authenticated with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56763'
  tag rid: 'SV-71023r1_rule'
  tag stig_id: 'SRG-OS-000109-GPOS-00056'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-61659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end

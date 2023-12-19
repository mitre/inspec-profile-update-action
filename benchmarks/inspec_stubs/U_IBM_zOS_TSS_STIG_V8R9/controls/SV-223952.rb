control 'SV-223952' do
  title 'CA-TSS user accounts must uniquely identify system users.'
  desc 'To assure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the UNIX and Windows operating systems offer a "switch user" capability allowing users to authenticate with their individual credentials and, when needed, "switch" to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the operating system without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.

'
  desc 'check', 'Obtain a list of all userids that are shared among multiple users (i.e., not uniquely identified system users).

If there are no shared userids on this domain, this is not a finding.

If there are shared userids on this domain, this is a finding.

NOTE: Userid'
  desc 'fix', 'Identify user accounts defined to the ESM that are being shared among multiple users. This may require interviews with appropriate system-level support personnel. Remove the shared user accounts from the ESM.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25625r516255_chk'
  tag severity: 'medium'
  tag gid: 'V-223952'
  tag rid: 'SV-223952r877793_rule'
  tag stig_id: 'TSS0-ES-000790'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-25613r516256_fix'
  tag satisfies: ['SRG-OS-000109-GPOS-00056', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000125-GPOS-00065']
  tag 'documentable'
  tag legacy: ['V-98611', 'SV-107715']
  tag cci: ['CCI-000770', 'CCI-000804', 'CCI-000877']
  tag nist: ['IA-2 (5)', 'IA-8', 'MA-4 c']
end

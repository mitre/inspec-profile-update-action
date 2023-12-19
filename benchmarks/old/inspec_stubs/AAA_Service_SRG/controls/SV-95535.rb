control 'SV-95535' do
  title 'AAA Services must be configured to prevent automatically disabling emergency accounts.'
  desc 'Emergency accounts are administrator accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account that is created for use by vendors or system maintainers, that is removed once the crisis has passed. When AAA Services do not perform account management, the connected Active Directory must provide this setting.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are configured to not automatically disable emergency accounts. Emergency accounts must not have a maximum lifetime set.

If AAA Services are configured to automatically disable emergency accounts, this is a finding.'
  desc 'fix', 'Configure AAA Services to not automatically disable emergency accounts. Emergency accounts must not have a maximum lifetime set.'
  impact 0.3
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80561r1_chk'
  tag severity: 'low'
  tag gid: 'V-80825'
  tag rid: 'SV-95535r1_rule'
  tag stig_id: 'SRG-APP-000234-AAA-000070'
  tag gtitle: 'SRG-APP-000234-AAA-000070'
  tag fix_id: 'F-87679r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end

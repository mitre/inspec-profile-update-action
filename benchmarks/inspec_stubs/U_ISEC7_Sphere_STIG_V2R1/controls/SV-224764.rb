control 'SV-224764' do
  title 'The ISEC7 EMM Suite server must be configured to have at least one user in the following Administrator roles: Security Administrator, Site Administrator, Help Desk User.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
 
The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
  desc 'check', 'Login to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration >> Global Permissions.
Verify for each Role (Security Administrator, Site Administrator, Help Desk User) that at least one user or AD group has been assigned.

If for each Role (Security Administrator, Site Administrator, Help Desk User) there is not at least one user (or AD group) assigned, this is a finding.'
  desc 'fix', 'Login to the ISEC7 EMM Suite console.
Navigate to Administration >> Configuration >> Global Permissions.
Assign at least one user or AD group to each of the following roles, Security Administrator, Site Administrator, Help Desk User.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26455r461548_chk'
  tag severity: 'medium'
  tag gid: 'V-224764'
  tag rid: 'SV-224764r505933_rule'
  tag stig_id: 'ISEC-06-000270'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-26443r461549_fix'
  tag 'documentable'
  tag legacy: ['V-97391', 'SV-106495']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end

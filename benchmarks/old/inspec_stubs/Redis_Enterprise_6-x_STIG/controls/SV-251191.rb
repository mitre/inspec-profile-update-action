control 'SV-251191' do
  title 'Redis Enterprise DBMS must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Auditing alerts can be selected on Redis Enterprise. With the RBAC settings, by default, only the Admin group can configure these events in the database. Additional roles with admin privileges can also be configured.

To view which roles have admin level privileges:
1. Log in to Redis Enterprise.
2. Navigate to the Access control tab and review the users listed therein.

To view which alerts are configured:
1. Log in to Redis Enterprise.
2. Navigate to the Databases tab.
3. Select any database to view and select the configuration tab.
4. Scroll down to determine which Alerts are selected to be emailed to the appropriate audiences (if any).

If designated personnel are not able to configure auditable events, this is a finding.'
  desc 'fix', "Configure the DBMS's settings to allow designated personnel to select which auditable events are audited. This can be done on Redis Enterprise with ACLs and RBAC.

To configure RBAC:
1. Log in to the Redis Control Plane as an admin user.
2. Navigate to the access control tab.
3. Provide the appropriate permissions and privileges as defined by the organization."
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54626r804761_chk'
  tag severity: 'medium'
  tag gid: 'V-251191'
  tag rid: 'SV-251191r804763_rule'
  tag stig_id: 'RD6X-00-001500'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-54580r804762_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end

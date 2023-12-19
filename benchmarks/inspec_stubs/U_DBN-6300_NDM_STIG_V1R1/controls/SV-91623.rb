control 'SV-91623' do
  title 'The DBN-6300 must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be generated and forwarded to the audit log.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories can be checked in accordance with the role assigned. For an administrator, the admin role should allow all categories to be checked for Audit Log, Syslog, and Audit Console.

Log off, log on again, and attempt to repeat the process logged on as a "lesser" user that does not have privileges to configure audit.

Attempt to modify the audit log categories. This should fail.

Following this verification, if it is possible for a non-privileged user with no audit log modification privileges to modify log functions, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog. Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76551r1_chk'
  tag severity: 'low'
  tag gid: 'V-76927'
  tag rid: 'SV-91623r1_rule'
  tag stig_id: 'DBNW-DM-000024'
  tag gtitle: 'SRG-APP-000090-NDM-000222'
  tag fix_id: 'F-83623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end

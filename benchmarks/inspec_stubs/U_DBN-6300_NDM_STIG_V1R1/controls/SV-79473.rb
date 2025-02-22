control 'SV-79473' do
  title 'The DBN-6300 must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. This control does not apply to the account of last resort or root account. DoD prohibits local user accounts on the device, except for an account of last resort and (where applicable) a root account.

With the DB-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an account creation. Confirm the presence of a syslog message on the syslog server containing the information for successful account creation.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a successful account creation has just occurred is not there, this is a finding.'
  desc 'fix', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an account creation. Confirm the presence of a syslog message on the syslog server containing the information for successful account creation.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-65641r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64983'
  tag rid: 'SV-79473r1_rule'
  tag stig_id: 'DBNW-DM-000009'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-70923r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end

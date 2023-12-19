control 'SV-91641' do
  title 'The DBN-6300 must generate audit records containing the full-text recording of privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

Organizations consider limiting the additional audit information to only that information explicitly needed for specific audit requirements. The additional information required is dependent on the type of information (i.e., sensitivity of the data and the environment in which it resides). At a minimum, the organization must audit full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an auditable action. Confirm the presence of a syslog message on the syslog server containing the full-text recording of privileged commands.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message for the event does not contain the full-text recording of privileged commands, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76569r1_chk'
  tag severity: 'low'
  tag gid: 'V-76945'
  tag rid: 'SV-91641r1_rule'
  tag stig_id: 'DBNW-DM-000033'
  tag gtitle: 'SRG-APP-000101-NDM-000231'
  tag fix_id: 'F-83641r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end

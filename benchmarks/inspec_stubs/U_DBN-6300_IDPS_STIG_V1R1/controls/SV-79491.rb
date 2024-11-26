control 'SV-79491' do
  title 'In the event of a logging failure caused by the lack of log record storage capacity, the DBN-6300 must continue generating and storing audit records if possible, overwriting the oldest audit records in a first-in-first-out manner.'
  desc 'It is critical that when the IDPS is at risk of failing to process audit logs as required, it takes action to mitigate the failure. 
 
The DBN-6300 performs a critical security function, so its continued operation is imperative. Since availability of the IDPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort.'
  desc 'check', 'Audit records are automatically backed up on a real-time basis via syslog when enabled.

Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log and verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process a successful account action (of any kind). Confirm the presence of a syslog message on the syslog server containing the information for whatever successful account action was taken.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a successful account action that was taken and had just occurred is not there, this is a finding.'
  desc 'fix', 'Audit records are automatically backed up on a real-time basis via syslog when enabled.

Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog server information is valid and that the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log and verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

When a network failure occurs, the audit records can be retrieved manually by downloading the records via the System State Report. This is done by navigating to Support - System State Report, "New Report" (file name is optional). A report will be generated. Using the download arrow on the right of the screen, download and examine the System State Report for the audit record showing the latest audit log.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65659r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65001'
  tag rid: 'SV-79491r1_rule'
  tag stig_id: 'DBNW-IP-000010'
  tag gtitle: 'SRG-NET-000089-IDPS-00069'
  tag fix_id: 'F-70941r6_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end

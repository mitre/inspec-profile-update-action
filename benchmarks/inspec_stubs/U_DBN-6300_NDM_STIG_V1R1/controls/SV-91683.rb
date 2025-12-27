control 'SV-91683' do
  title 'The DBN-6300 must provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near-real-time, within minutes, or within hours.

The individuals or roles to change the auditing are dependent on the security configuration of the network device. For example, it may be configured to allow only some administrators to change the auditing, while other administrators can review audit logs but not reconfigure auditing. Because this capability is so powerful, organizations should be extremely cautious about only granting this capability to fully authorized security personnel.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are able to be selected based on selectable event criteria for Audit Log, Syslog, and Audit Console.

If, after navigating to Settings >> Advanced >> Audit Log, there is no facility to change the auditing to be performed within the system log based on selectable event criteria, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76613r1_chk'
  tag severity: 'low'
  tag gid: 'V-76987'
  tag rid: 'SV-91683r1_rule'
  tag stig_id: 'DBNW-DM-000096'
  tag gtitle: 'SRG-APP-000353-NDM-000292'
  tag fix_id: 'F-83683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end

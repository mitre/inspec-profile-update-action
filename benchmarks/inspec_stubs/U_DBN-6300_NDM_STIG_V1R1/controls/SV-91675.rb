control 'SV-91675' do
  title 'The DBN-6300 must activate a system alert message, send an alarm, and/or automatically shut down when a component failure is detected.'
  desc "Predictable failure prevention requires organizational planning to address device failure issues. If components key to maintaining the device's security fail to function, the device could continue operating in a nonsecure state. If appropriate actions are not taken when a network device failure occurs, a denial-of-service condition may occur that could result in mission failure because the network would be operating without a critical security monitoring and prevention function. Upon detecting a failure of network device security components, the network device must activate a system alert message, send an alarm, or shut down.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled."
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and that the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process any account function. Confirm the presence of a syslog message on the syslog server containing the information for whatever that account function represented.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information for the account action that took place is not present, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76605r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76979'
  tag rid: 'SV-91675r1_rule'
  tag stig_id: 'DBNW-DM-000078'
  tag gtitle: 'SRG-APP-000268-NDM-000274'
  tag fix_id: 'F-83675r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end

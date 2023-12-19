control 'SV-79507' do
  title 'The DBN-6300 must off-load log records to a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised. 
 
This also prevents the log records from being lost if the logs stored locally are accidentally or intentionally deleted, altered, or corrupted.'
  desc 'check', 'Audit records are automatically backed up on a real-time basis via syslog when enabled. 
 
Verify the DBN-6300 is connected to the syslog server. 
 
Navigate to Settings >> Advanced >> Syslog. 
 
Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected. 
 
Navigate to Settings >> Advanced >> Audit Log. 
 
Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console. 
 
Following this verification, process an account action. Confirm the presence of a syslog message on the syslog server containing the details of this account action. 
 
If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information with the details of this account action is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed. 
 
Navigate to Settings >> Advanced >> Syslog. 
 
Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable". 
 
Navigate to Settings >> Advanced >> Audit Log. 
 
Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console. 
 
If the "Use System Syslog" button is not set to "Yes", press the "Yes" button. 
 
Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65675r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65017'
  tag rid: 'SV-79507r1_rule'
  tag stig_id: 'DBNW-IP-000039'
  tag gtitle: 'SRG-NET-000334-IDPS-00191'
  tag fix_id: 'F-70957r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

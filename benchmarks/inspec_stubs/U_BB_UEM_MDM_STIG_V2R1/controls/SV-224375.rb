control 'SV-224375' do
  title 'The BlackBerry UEM server must be configured to transfer BlackBerry UEM server logs to another server for storage, analysis, and reporting. 

Note: BlackBerry UEM server logs include logs of MDM events and logs transferred to the BlackBerry UEM server by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the BlackBerry UEM server has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the BlackBerry UEM server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) c.8, FAU_STG_EXT.1.1(1)'
  desc 'check', 'Review the Syslog audit records from the syslog audit management server and verify UEM logs are included.

If UEM logs are not found on the Syslog server, this is a finding.'
  desc 'fix', %q(The Admin must access the UEM server.
Configuring trust: 
1. Get the CA that signs the Syslog server cert.
2. Upload the CA into the UEM server.
 - From the CMD prompt on the UEM server follow the instructions found on page 70-71 of the Admin Guide, "Setup export of server audit records to a syslog server".
3. Configure UEM to send audit data to the Syslog server.
 - Copy the script in Appendix A of the Admin Guide.
 - In the script, change the hostname and port number to match your environment.
 - Set the host name and port number, for example:
 SET @v_hostname = 'localhost';
 SET @v_port = '31000';
4. Execute the SQL script against the BlackBerry UEM database. 
5. Restart the BlackBerry UEM Core service.)
  impact 0.5
  ref 'DPMS Target BlackBerry UEM'
  tag check_id: 'C-26052r539025_chk'
  tag severity: 'medium'
  tag gid: 'V-224375'
  tag rid: 'SV-224375r604136_rule'
  tag stig_id: 'BUEM-00-000500'
  tag gtitle: 'PP-MDM-411054'
  tag fix_id: 'F-26040r539026_fix'
  tag 'documentable'
  tag legacy: ['SV-111867', 'V-102905']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

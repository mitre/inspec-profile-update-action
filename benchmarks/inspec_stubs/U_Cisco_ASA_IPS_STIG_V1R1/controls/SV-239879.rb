control 'SV-239879' do
  title 'The Cisco ASA must be configured to off-load log records to a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

This also prevents the log records from being lost if the logs stored locally are accidentally or intentionally deleted, altered, or corrupted.'
  desc 'check', 'Verify that a syslog server has been defined.

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies > Actions Alerts. The Alerts page appears.

Step 2: Verify the IP address and port number of the syslog server.

If the Cisco ASA is not configured to send log records to a centralized log server, this is a finding.'
  desc 'fix', 'Configure Firepower to send log records to a syslog server as shown in the following steps:

Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Actions Alerts.

Step 2: Click the Create Alert drop-down menu and choose option Create Syslog Alert. 

Step 3: Enter the following values for the Syslog server:
   Host:  Specify the IP address/hostname of Syslog server.
   Port:  Specify the port number of Syslog server.

Step 4: Click Store ASA FirePOWER Changes.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43112r665948_chk'
  tag severity: 'medium'
  tag gid: 'V-239879'
  tag rid: 'SV-239879r665950_rule'
  tag stig_id: 'CASA-IP-000110'
  tag gtitle: 'SRG-NET-000334-IDPS-00191'
  tag fix_id: 'F-43071r665949_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

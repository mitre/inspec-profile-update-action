control 'SV-239880' do
  title 'The Cisco ASA must be configured to send log records to the syslog server for specific facility and severity level.'
  desc 'Without the capability to generate audit records with a severity code it is difficult to track and handle detection events.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The IDPS must have the capability to collect and log the severity associated with the policy, rule, or signature. IDPS products often have either pre-configured and/or a configurable method for associating an impact indicator or severity code with signatures and rules, at a minimum.'
  desc 'check', 'Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Actions Alerts. The Alerts page appears.

Step 2: Verify a facility has been selected for the syslog server.

If the Cisco ASA Firepower is not configured to send log records to the syslog server for specific facility and severity level, this is a finding.'
  desc 'fix', 'Step 1: Navigate to Configuration >> ASA Firepower Configuration >> Policies >> Actions Alerts. 

Step 2: Click the Create Alert drop-down menu and choose option Create Syslog Alert.

Step 3: Enter the following values for the Syslog server:
   Facility:  Select any facility that is configured on your Syslog server.
   Severity:  Select any severity that is configured on your Syslog server.

Step 4: Click Store ASA FirePOWER Changes.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43113r665951_chk'
  tag severity: 'medium'
  tag gid: 'V-239880'
  tag rid: 'SV-239880r665953_rule'
  tag stig_id: 'CASA-IP-000120'
  tag gtitle: 'SRG-NET-000113-IDPS-00189'
  tag fix_id: 'F-43072r665952_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

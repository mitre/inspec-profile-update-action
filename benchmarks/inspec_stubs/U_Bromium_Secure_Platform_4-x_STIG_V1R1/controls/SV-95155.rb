control 'SV-95155' do
  title 'The Bromium Enterprise Controller (BEC) must send history.log records to a central log server (i.e., syslog server).'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

History.log contains log records of administrative actions such as adding users or changing user privileges. This requirement requires that the content captured in audit records be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application components requiring centralized audit log management must have the capability to support centralized management.

Note: The central log server must be configured with alerts and notifications that are required by the various requirements in this STIG. It must also be configured to alert the ISSO and system administrator when communications is lost with the BEC.'
  desc 'check', 'Ask the site representatives if they have developed and implemented a solution for storing the contents of "history.log".

Check that the backup solution has been configured to include the "history.log" files residing on the BEC.
 
If the BEC does not send "history.log" records to a central log server (i.e., syslog server), this is a finding.'
  desc 'fix', %q(Automatically forward all contents of "history.log" to the site's central log server in real time. 

Install the file monitoring agent that is provided by the site's centralized events server (e.g., syslog, SIEM) and configure to monitor and forward "history.log" (example: C:\Program Data\Bromium\BMS\Logs\history.log). Follow the instructions included with the central log server.)
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80451'
  tag rid: 'SV-95155r1_rule'
  tag stig_id: 'BROM-00-000765'
  tag gtitle: 'SRG-APP-000356'
  tag fix_id: 'F-87257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end

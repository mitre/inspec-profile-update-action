control 'SV-214315' do
  title 'The log information from the Apache web server must be protected from unauthorized deletion and modification.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of log records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized modification. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from modification by non-privileged users.

'
  desc 'check', %q(Query the System Administrator (SA) to determine who has update access to the web server log files. 

The role of auditor and the role of SA should be distinctly separate. An individual functioning as an auditor should not also serve as an SA due to a conflict of interest.

Only management-authorized individuals with a privileged ID or group ID associated with an auditor role will have access permission to log files that are greater than read on web servers he or she has been authorized to audit.

Only management-authorized individuals with a privileged ID or group ID associated with either an SA or Web Administrator role may have read authority to log files for the web servers he or she has been authorized to administer.

If an account with roles other than auditor has greater than read authority to the log files, this is a finding.

Obtain the log location by reviewing the <'INSTALL PATH'>\conf\httpd.conf file.

Click the "Browse" button and navigate to the directory where the log files are stored.

Right-click the log file name to review and click "Properties".

Click the "Security" tab.

If an account associated with roles other than auditors, SAs, or Web Administrators has any access to log files, this is a finding.

If an account with roles other than auditor has greater than read authority to the log files, this is a finding.

This check does not apply to service account IDs used by automated services necessary to process, manage, and store log files.)
  desc 'fix', %q(Obtain the log location by reviewing the <'INSTALL PATH'>\conf\httpd.conf file.

Click the "Browse" button and navigate to the directory where the log files are stored.

Right-click the log file name to review and click "Properties".

Click the "Security" tab.

Set the log file permissions for the appropriate group(s).

Click "OK".

Select "Apply" in the "Actions" pane.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15527r277448_chk'
  tag severity: 'medium'
  tag gid: 'V-214315'
  tag rid: 'SV-214315r505936_rule'
  tag stig_id: 'AS24-W1-000200'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-15525r277449_fix'
  tag satisfies: ['SRG-APP-000120-WSR-000070', 'SRG-APP-000119-WSR-000069']
  tag 'documentable'
  tag legacy: ['SV-102451', 'V-92363']
  tag cci: ['CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a']
end

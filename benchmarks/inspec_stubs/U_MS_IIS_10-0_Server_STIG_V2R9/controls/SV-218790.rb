control 'SV-218790' do
  title 'The log information from the IIS 10.0 web server must be protected from unauthorized modification or deletion.'
  desc "A major tool in exploring the website use, attempted use, unusual conditions, and problems are the access and error logs. In the event of a security incident, these logs can provide the System Administrator (SA) and the web manager with valuable information. Failure to protect log files could enable an attacker to modify the log file data or falsify events to mask an attacker's activity.

"
  desc 'check', 'This check does not apply to service account IDs utilized by automated services necessary to process, manage, and store log files.
Open the IIS 10.0 Manager.
Click the IIS 10.0 web server name.
Click the "Logging" icon.
Click "Browse" and navigate to the directory where the log files are stored.
Right-click the log file directory to review.
Click "Properties".
Click the "Security" tab.
Verify log file access is restricted as follows. Otherwise, this is a finding.
SYSTEM - Full Control
Administrators - Full Control'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Click "Browse" and navigate to the directory where the log files are stored.

Right-click the log file directory to review and click "Properties".

Click the "Security" tab.

Set the log file permissions for the appropriate group(s).

Click "OK".

Select "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20262r570471_chk'
  tag severity: 'medium'
  tag gid: 'V-218790'
  tag rid: 'SV-218790r879578_rule'
  tag stig_id: 'IIST-SV-000115'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-20260r570472_fix'
  tag satisfies: ['SRG-APP-000120-WSR-000070', 'SRG-APP-000118-WSR-000068', 'SRG-APP-000118-WSR-000069']
  tag 'documentable'
  tag legacy: ['SV-109219', 'V-100115']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end

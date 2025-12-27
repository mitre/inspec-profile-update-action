control 'SV-237150' do
  title 'ColdFusion must log scheduled tasks.'
  desc 'Application server logging capability is critical for accurate forensic analysis.  Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct location or process within the application server where the events occurred is important during forensic analysis.  To determine where an event occurred, the log data must contain data such as application components, modules, session identifiers, filenames, host names, and functionality.

ColdFusion inherently logs the location of events that take place during the normal operation of the application server, but the Executive task scheduler is not logged by default.  Logging the execution of a task through the scheduler helps the administrator understand how a task was executed and also aides the administrator recognize if unauthorized scheduled tasks have been created.'
  desc 'check', 'Within the Administrator Console, navigate to the "Logging Settings" page under the "Debugging & Logging" menu.

If "Enable logging for scheduled tasks" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Logging Settings" page under the "Debugging & Logging" menu.  Check "Enable logging for scheduled tasks"  and select the "Submit Changes" button.'
  impact 0.3
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40369r641543_chk'
  tag severity: 'low'
  tag gid: 'V-237150'
  tag rid: 'SV-237150r641545_rule'
  tag stig_id: 'CF11-02-000040'
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag fix_id: 'F-40332r641544_fix'
  tag 'documentable'
  tag legacy: ['SV-76863', 'V-62373']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

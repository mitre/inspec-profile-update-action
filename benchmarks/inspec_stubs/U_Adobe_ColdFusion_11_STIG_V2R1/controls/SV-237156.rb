control 'SV-237156' do
  title 'ColdFusion must send log records to the operating system logging facility.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. By sending some of the log messages to the operating system logging facilities, these log messages become part of the OS log history, become part of the log review performed by the OS administrator, and become part of the backup of OS log data.

Note: This feature is only available for Linux installations.'
  desc 'check', 'This feature is not present when ColdFusion is installed on Windows; therefore, this finding is not applicable.

Within the Administrator Console, navigate to the "Logging Settings" page under the "Debugging & Logging" menu.

If "Use operating system logging facilities" is not checked, this is a finding.'
  desc 'fix', 'Navigate to the "Logging Settings" page under the "Debugging & Logging" menu.  Check "Use operating system logging facilities"  and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40375r641561_chk'
  tag severity: 'medium'
  tag gid: 'V-237156'
  tag rid: 'SV-237156r641563_rule'
  tag stig_id: 'CF11-02-000057'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag fix_id: 'F-40338r641562_fix'
  tag 'documentable'
  tag legacy: ['SV-76875', 'V-62385']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end

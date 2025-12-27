control 'SV-81541' do
  title 'The LogFileSize on Tanium Servers must be enabled with a value of 104857600 (100MB) or more.'
  desc "Although a full set of usage logs for each Tanium component is, by default, no more than 100 MB, logging is initially disabled to minimize impact to any computers that might be critically low on disk space and must be explicitly enabled.

To ensure logs retain enough forensic, the logs must be configured to grow to a large enough size. Specifying at least 10MB for clients, the log file will grow to 10MB before rolling over.

Tanium Server's log size should be a minimum of 100MB before rolling over in order to retain enough forensic data for analysis."
  desc 'check', 'Access the Tanium App server through interactive logon.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Validate the value for REG_DWORD "LogFileSizeInBytes" is set to "104857600" or greater.

If the value for REG_DWORD "LogFileSizeInBytes" is not set to "104857600" or greater, this is a finding.'
  desc 'fix', 'Access the Tanium App server through interactive logon.

Run regedit as Administrator.

Navigate to HKLM\\Software\\Wow6432Node\\Tanium\\Tanium Server.

Set the value for REG_DWORD "LogFileSizeInBytes" to "104857600" or greater.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67687r2_chk'
  tag severity: 'medium'
  tag gid: 'V-67051'
  tag rid: 'SV-81541r2_rule'
  tag stig_id: 'TANS-SV-000009'
  tag gtitle: 'SRG-APP-000100'
  tag fix_id: 'F-73151r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

control 'SV-77023' do
  title 'ColdFusion must have Allow Line Debugging disabled.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team.

The option to allow line debugging is enabled when a developer wants to trace code through a debugger such as Eclipse.  Debugging must not be performed on a production server, and this option must be disabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Debugger Settings" page under the "Debugging & Output Settings" menu.

If "Allow Line Debugging" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Debugger Settings" page under the "Debugging & Output Settings" menu.  Uncheck "Allow Line Debugging" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63337r1_chk'
  tag severity: 'high'
  tag gid: 'V-62533'
  tag rid: 'SV-77023r1_rule'
  tag stig_id: 'CF11-06-000221'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-68453r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

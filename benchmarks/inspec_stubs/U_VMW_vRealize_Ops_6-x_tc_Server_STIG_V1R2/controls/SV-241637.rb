control 'SV-241637' do
  title 'tc Server ALL must exclude documentation, sample code, example applications, and tutorials.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.).

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. Because tc Server is installed as part of the entire vROps application, and not installed separately, VMware has ensured that all documentation, sample code, example applications, and tutorials have been removed from tc Server as part of the build process.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the web server documentation and deployed configuration to determine if documentation, sample code, example applications, and tutorials have been removed.

If documentation, sample code, example applications, and tutorials have not been removed, this is a finding.'
  desc 'fix', 'Document the removal of all documentation, sample code, example applications, and tutorials and ensure the web server configuration does not contain any documentation, sample code, example applications, and tutorials.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44913r684147_chk'
  tag severity: 'high'
  tag gid: 'V-241637'
  tag rid: 'SV-241637r879587_rule'
  tag stig_id: 'VROM-TC-000355'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-44872r683772_fix'
  tag 'documentable'
  tag legacy: ['SV-99559', 'V-88909']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

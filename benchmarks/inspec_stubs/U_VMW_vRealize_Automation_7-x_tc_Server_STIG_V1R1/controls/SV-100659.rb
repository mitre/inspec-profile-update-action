control 'SV-100659' do
  title 'tc Server ALL must exclude documentation, sample code, example applications, and tutorials.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. Because tc Server is installed as part of the entire vRA application, and not installed separately, VMware has ensured that all documentation, sample code, example applications, and tutorials have been removed from tc Server as part of the build process.'
  desc 'check', 'Interview the ISSO.

Review the web server documentation and deployed configuration to determine if documentation, sample code, example applications, and tutorials have been removed.

If documentation, sample code, example applications, and tutorials have not been removed, this is a finding.'
  desc 'fix', 'Remove all documentation, sample code, example applications, and tutorials.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89701r1_chk'
  tag severity: 'high'
  tag gid: 'V-90009'
  tag rid: 'SV-100659r1_rule'
  tag stig_id: 'VRAU-TC-000345'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-96751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

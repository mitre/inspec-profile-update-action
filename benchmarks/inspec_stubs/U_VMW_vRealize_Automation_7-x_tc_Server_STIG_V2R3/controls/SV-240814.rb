control 'SV-240814' do
  title 'tc Server ALL baseline must be documented and maintained.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

Because tc Server is installed as part of the entire vRA application, and not installed separately, VMware has ensured that all updates, upgrades, and patches have been thoroughly tested before becoming part of the production build process.'
  desc 'check', 'Interview the ISSO.

Review the web server documentation and deployed configuration to determine if the tc Server code baseline is documented and maintained.

If the tc Server code baseline is not documented and maintained, this is a finding.'
  desc 'fix', 'Develop baseline documentation of the tc Server codebase.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44047r674184_chk'
  tag severity: 'medium'
  tag gid: 'V-240814'
  tag rid: 'SV-240814r879640_rule'
  tag stig_id: 'VRAU-TC-000550'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-44006r674185_fix'
  tag 'documentable'
  tag legacy: ['SV-100709', 'V-90059']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

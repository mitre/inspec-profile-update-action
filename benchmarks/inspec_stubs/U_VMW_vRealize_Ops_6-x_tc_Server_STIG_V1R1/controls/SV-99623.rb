control 'SV-99623' do
  title 'tc Server ALL baseline must be documented and maintained.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

Because tc Server is installed as part of the entire vROps application, and not installed separately, VMware has ensured that all updates, upgrades, and patches have been thoroughly tested before becoming part of the production build process.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the web server documentation and deployed configuration to determine if the tc Server code baseline is documented and maintained.

If the tc Server code baseline is not documented and maintained, this is a finding.'
  desc 'fix', 'Develop baseline documentation of the tc Server codebase and ensure the tc Server baseline is configured properly.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88973'
  tag rid: 'SV-99623r1_rule'
  tag stig_id: 'VROM-TC-000575'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-95715r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

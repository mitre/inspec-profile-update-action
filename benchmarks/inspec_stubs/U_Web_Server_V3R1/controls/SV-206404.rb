control 'SV-206404' do
  title 'The web server must augment re-creation to a stable and known baseline.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

When the web server does not offer a method to roll back to a clean baseline, external methods, such as a baseline snapshot or virtualizing the web server, can be used.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if the web server offers the capability to reinstall from a known state.

If the web server does not offer this capability, determine if the web server, in any manner, prohibits the reinstallation of a known state.

If the web server does prohibit the reinstallation to a known state, this is a finding.'
  desc 'fix', 'Configure the web server to augment and not hinder the reinstallation of a known and stable baseline.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6665r377804_chk'
  tag severity: 'medium'
  tag gid: 'V-206404'
  tag rid: 'SV-206404r397738_rule'
  tag stig_id: 'SRG-APP-000225-WSR-000074'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-6665r377805_fix'
  tag 'documentable'
  tag legacy: ['SV-70283', 'V-56029']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

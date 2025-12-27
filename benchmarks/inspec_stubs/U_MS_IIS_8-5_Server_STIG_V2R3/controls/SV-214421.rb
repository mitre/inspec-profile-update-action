control 'SV-214421' do
  title 'The IIS 8.5 web server must augment re-creation to a stable and known baseline.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

When the web server does not offer a method to roll back to a clean baseline, external methods, such as a baseline snapshot or virtualizing the web server, can be used.'
  desc 'check', 'Interview the System Administrator for the IIS 8.5 web server.

Ask for documentation on the disaster recovery methods tested and planned for the IIS 8.5 web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.'
  desc 'fix', 'Prepare documentation for disaster recovery methods for the IIS 8.5 web server in the event of the necessity for rollback.

Document and test the disaster recovery methods designed.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15631r310311_chk'
  tag severity: 'medium'
  tag gid: 'V-214421'
  tag rid: 'SV-214421r508658_rule'
  tag stig_id: 'IISW-SV-000136'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-15629r310312_fix'
  tag 'documentable'
  tag legacy: ['SV-91425', 'V-76729']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

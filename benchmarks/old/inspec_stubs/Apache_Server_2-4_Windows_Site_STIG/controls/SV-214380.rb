control 'SV-214380' do
  title 'The Apache web server must augment re-creation to a stable and known baseline.'
  desc 'Making certain that the web server has not been updated by an unauthorized user is always a concern. Adding patches, functions, and modules that are untested and not part of the baseline opens the possibility for security risks. The web server must offer, and not hinder, a method that allows for the quick and easy reinstallation of a verified and patched baseline to guarantee the production web server is up-to-date and has not been modified to add functionality or expose security risks.

When the web server does not offer a method to roll back to a clean baseline, external methods, such as a baseline snapshot or virtualizing the web server, can be used.'
  desc 'check', 'Interview the System Administrator for the Apache web server.

Ask for documentation on the disaster recovery methods tested and planned for the Apache web server in the event of the necessity for rollback.

If documentation for a disaster recovery has not been established, this is a finding.'
  desc 'fix', 'Prepare documentation for disaster recovery methods for the Apache web server in the event of the necessity for rollback.

Document and test the disaster recovery methods designed.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15591r277881_chk'
  tag severity: 'medium'
  tag gid: 'V-214380'
  tag rid: 'SV-214380r397738_rule'
  tag stig_id: 'AS24-W2-000540'
  tag gtitle: 'SRG-APP-000225-WSR-000074'
  tag fix_id: 'F-15589r277882_fix'
  tag 'documentable'
  tag legacy: ['SV-102633', 'V-92545']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

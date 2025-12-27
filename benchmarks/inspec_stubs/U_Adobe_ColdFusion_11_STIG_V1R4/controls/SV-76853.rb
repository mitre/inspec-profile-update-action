control 'SV-76853' do
  title 'ColdFusion must control user access to Exposed Services.'
  desc "ColdFusion exposes many existing services as web services.  These services, such as cfpdf, cfmail and cfpop, can be accessed by users and applications written in other languages and technologies than ColdFusion CFML.  To invoke the services, the client must be on the allowed IP list and have a user account with the proper privileges to the exposed services.  Exposing these services expands the security risk and potential for compromise of the ColdFusion application server.  If a need arises for these services, then only those user accounts requiring access to perform the user's duties must be given access."
  desc 'check', %q(Within the Administrator Console, navigate to the "User Manager" page under the "Security" menu.  Review each defined user by using the edit function.  For each user that has values for "Allowed Services", validate with the SA that the user should have remote access to each service.

If there are any users with services that are not required to perform the users' duties, this is a finding.)
  desc 'fix', %q(Navigate to the "User Manager" page under the "Security" menu.  Only assign services to those users who require access and only assign those services that are required to perform the user's duties.)
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62363'
  tag rid: 'SV-76853r1_rule'
  tag stig_id: 'CF11-01-000018'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-68283r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end

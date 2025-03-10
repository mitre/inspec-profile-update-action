control 'SV-45825' do
  title 'Administrative accounts must not run a web browser, except as needed for local service administration.'
  desc "If a web browser flaw is exploited while running as a privileged user, the entire system could be compromised.

Specific exceptions for local service administration should be documented in site-defined policy.  These exceptions may include HTTP(S)-based tools used for the administration of the local system, services, or attached devices.  Examples of possible exceptions are HP’s System Management Homepage (SMH), the CUPS administrative interface, and Sun's StorageTek Common Array Manager (CAM) when these services are running on the local system."
  desc 'check', 'Interview the SA to determine if a site-defined policy exists which requires administrative accounts to use web browsers only for local service administration. If a site-defined policy does not exist this is a finding.'
  desc 'fix', 'Enforce a site-defined policy requiring administrative accounts use web browsers only for local service administration.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43143r1_chk'
  tag severity: 'high'
  tag gid: 'V-4382'
  tag rid: 'SV-45825r1_rule'
  tag stig_id: 'GEN004220'
  tag gtitle: 'GEN004220'
  tag fix_id: 'F-39212r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

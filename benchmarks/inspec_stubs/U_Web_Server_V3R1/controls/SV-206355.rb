control 'SV-206355' do
  title 'The web server must enforce approved authorizations for logical access to hosted applications and resources in accordance with applicable access control policies.'
  desc 'To control access to sensitive information and hosted applications by entities that have been issued certificates by DoD-approved PKIs, the web server must be properly configured to incorporate a means of authorization that does not simply rely on the possession of a valid certificate for access. Access decisions must include a verification that the authenticated entity is permitted to access the information or application. Authorization decisions must leverage a variety of methods, such as mapping the validated PKI certificate to an account with an associated set of permissions on the system. If the web server relied only on the possession of the certificate and did not map to system roles and privileges, each user would have the same abilities and roles to make changes to the production system.'
  desc 'check', 'The web server must be configured to perform an authorization check to verify that the authenticated entity should be granted access to the requested content.

If the web server does not verify that the authenticated entity is authorized to access the requested content prior to granting access, this is a finding.'
  desc 'fix', "Configure the web server to validate the authenticated entity's authorization to access requested content prior to granting access."
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6616r377657_chk'
  tag severity: 'medium'
  tag gid: 'V-206355'
  tag rid: 'SV-206355r395499_rule'
  tag stig_id: 'SRG-APP-000033-WSR-000169'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-6616r377658_fix'
  tag 'documentable'
  tag legacy: ['SV-70199', 'V-55945']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

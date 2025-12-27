control 'SV-99799' do
  title 'HAProxy files must be verified for their integrity (checksums) before being added to the build systems.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.

The HAProxy web server files on vRA must be part of a documented build process. Checksums of the production files must be available to verify their integrity.'
  desc 'check', 'Interview the ISSO.

Determine whether web server files are verified/validated before being implemented into the production environment.

If the web server files are not verified or validated before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Ensure web server files are verified or validated before being implemented the production environment.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89149'
  tag rid: 'SV-99799r1_rule'
  tag stig_id: 'VRAU-HA-000115'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-95891r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

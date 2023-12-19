control 'SV-206372' do
  title 'All web server files must be verified for their integrity (e.g., checksums and hashes) before becoming part of the production web server.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information. 

The web server or hosting system must have a mechanism to verify that files, before installation, are valid.

Examples of validation methods are sha1 and md5 hashes and checksums.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine if the web server validates files before the files are implemented into the running configuration.

If the web server does not meet this requirement and an external facility is not available for use, this is a finding.'
  desc 'fix', 'Configure the web server to verify object integrity before becoming part of the production web server or utilize an external tool designed to meet this requirement.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6633r377708_chk'
  tag severity: 'medium'
  tag gid: 'V-206372'
  tag rid: 'SV-206372r879584_rule'
  tag stig_id: 'SRG-APP-000131-WSR-000051'
  tag gtitle: 'SRG-APP-000131'
  tag fix_id: 'F-6633r377709_fix'
  tag 'documentable'
  tag legacy: ['SV-70237', 'V-55983']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

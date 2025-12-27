control 'SV-240781' do
  title 'tc Server ALL server files must be verified for their integrity (e.g., checksums and hashes) before becoming part of the production web server.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information. 

VMware delivers product updates and patches regularly. It is crucial that system administrators coordinate installation of product updates with the site ISSO to ensure that only valid files are uploaded onto the system.'
  desc 'check', 'Interview the ISSO.

Determine whether web server files are being fully reviewed, tested, and signed before being implemented into the production environment.

If the web server files are not being fully reviewed, tested, and signed before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Configure the web server to verify object integrity before becoming part of the production web server or utilize an external tool designed to meet this requirement.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44014r854837_chk'
  tag severity: 'medium'
  tag gid: 'V-240781'
  tag rid: 'SV-240781r879584_rule'
  tag stig_id: 'VRAU-TC-000310'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-43973r674086_fix'
  tag 'documentable'
  tag legacy: ['SV-100647', 'V-89997']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

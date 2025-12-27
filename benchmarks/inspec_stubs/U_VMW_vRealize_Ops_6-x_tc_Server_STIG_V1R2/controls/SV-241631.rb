control 'SV-241631' do
  title 'tc Server ALL server files must be verified for their integrity (e.g., checksums and hashes) before becoming part of the production web server.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.

VMware delivers product updates and patches regularly. It is crucial that system administrators coordinate installation of product updates with the site ISSO to ensure that only valid files are uploaded onto the system.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine whether web server files are being fully reviewed, tested, and signed before being implemented into the production environment.

If the web server files are not being fully reviewed, tested, and signed before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Configure the web server to verify object integrity before becoming part of the production web server or utilize an external tool designed to meet this requirement.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44907r854899_chk'
  tag severity: 'medium'
  tag gid: 'V-241631'
  tag rid: 'SV-241631r879584_rule'
  tag stig_id: 'VROM-TC-000320'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-44866r683754_fix'
  tag 'documentable'
  tag legacy: ['SV-99547', 'V-88897']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

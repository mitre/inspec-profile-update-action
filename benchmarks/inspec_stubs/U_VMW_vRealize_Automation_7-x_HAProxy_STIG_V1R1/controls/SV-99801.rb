control 'SV-99801' do
  title 'HAProxy expansion modules must be verified for their integrity (checksums) before being added to the build systems.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information.

Expansion that are installed on the production HAProxy web server on vRA must be part of a documented build process. Checksums of the production files must be available to verify their integrity.'
  desc 'check', 'Interview the ISSO.

Determine whether expansion modules are being fully reviewed, tested, and signed before being implemented into the production environment.

If the expansion modules are not being fully reviewed, tested, and signed before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Ensure expansion modules are fully reviewed, tested, and signed before being implemented into the production environment.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89151'
  tag rid: 'SV-99801r1_rule'
  tag stig_id: 'VRAU-HA-000120'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-95893r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

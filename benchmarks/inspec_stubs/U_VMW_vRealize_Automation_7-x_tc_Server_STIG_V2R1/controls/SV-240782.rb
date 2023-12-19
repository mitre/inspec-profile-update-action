control 'SV-240782' do
  title 'tc Server ALL expansion modules must be fully reviewed, tested, and signed before they can exist on a production web server.'
  desc 'In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website. The process of developing on a functional production website entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and logon schemes is high in this situation. The existence of such immature content on a web server represents a significant security risk that is totally avoidable.

VMware delivers product updates and patches regularly. It is crucial that system administrators coordinate installation of product updates with the site ISSO to ensure that only valid files are uploaded onto the system.'
  desc 'check', 'Interview the ISSO.

Determine whether expansion modules are being fully reviewed, tested, and signed before being implemented into the production environment.

If the expansion modules are not being fully reviewed, tested, and signed before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Configure the web server to enforce, internally or through an external utility, the review, testing and signing of modules before implementation into the production environment.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44015r674427_chk'
  tag severity: 'medium'
  tag gid: 'V-240782'
  tag rid: 'SV-240782r674428_rule'
  tag stig_id: 'VRAU-TC-000315'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-43974r674089_fix'
  tag 'documentable'
  tag legacy: ['SV-100649', 'V-89999']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

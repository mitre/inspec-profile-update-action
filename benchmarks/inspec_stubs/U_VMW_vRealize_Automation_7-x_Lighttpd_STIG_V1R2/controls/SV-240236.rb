control 'SV-240236' do
  title 'Lighttpd expansion modules must be verified for their integrity before being added to a production web server.'
  desc 'Being able to verify that a patch, upgrade, certificate, etc., being added to the web server is unchanged from the producer of the file is essential for file validation and non-repudiation of the information. 

Expansion modules that are installed on the production Lighttpd web server on vRA must be part of a documented build process. Checksums of the production files must be available to verify their integrity.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine whether expansion modules are being fully reviewed, tested, and signed before being implemented into the production environment.

If the expansion modules are not being fully reviewed, tested, and signed before being implemented into the production environment, this is a finding.'
  desc 'fix', 'Review, test, and sign expansion modules before being implemented into the production environment.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43469r854810_chk'
  tag severity: 'medium'
  tag gid: 'V-240236'
  tag rid: 'SV-240236r879584_rule'
  tag stig_id: 'VRAU-LI-000150'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-43428r667884_fix'
  tag 'documentable'
  tag legacy: ['SV-99905', 'V-89255']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

control 'SV-32329' do
  title 'Web server/site administration must be performed over a secure path.'
  desc 'Logging into a web server remotely using an unencrypted protocol or service when performing updates and maintenance is a major risk.  Data, such as user account, is transmitted in plaintext and can easily be compromised.  When performing remote administrative tasks, a protocol or service that encrypts the communication channel must be used.

An alternative to remote administration of the web server is to perform web server administration locally at the console.  Local administration at the console implies physical access to the server.'
  desc 'check', 'If web administration is performed at the console, this check is NA.

If web administration is performed remotely the following checks will apply:

If administration of the server is performed remotely, it will only be performed securely by system administrators.

If web site administration or web application administration has been delegated, those users will be documented and approved by the ISSO.

Remote administration must be in compliance with any requirements contained within the Windows Server STIGs, and any applicable network STIGs.

Remote administration of any kind will be restricted to documented and authorized personnel.

All users performing remote administration must be authenticated.

All remote sessions will be encrypted and they will utilize FIPS 140-2 approved protocols.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

Review with site management how remote administration, if applicable, is configured on the web site.

If remote management meets the criteria listed above, this is not a finding.

If remote management is utilized and does not meet the criteria listed above, this is a finding.'
  desc 'fix', 'Ensure the web server administration is only performed over a secure path.'
  impact 0.7
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32735r2_chk'
  tag severity: 'high'
  tag gid: 'V-2249'
  tag rid: 'SV-32329r3_rule'
  tag stig_id: 'WG230 IIS7'
  tag gtitle: 'WG230'
  tag fix_id: 'F-29062r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end

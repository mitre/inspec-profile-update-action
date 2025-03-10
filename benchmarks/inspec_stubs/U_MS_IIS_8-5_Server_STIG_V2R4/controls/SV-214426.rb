control 'SV-214426' do
  title 'Remote access to the IIS 8.5 web server must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements.'
  desc 'Logging into a web server remotely using an unencrypted protocol or service when performing updates and maintenance is a major risk. Data, such as user account, is transmitted in plaintext and can easily be compromised. When performing remote administrative tasks, a protocol or service that encrypts the communication channel must be used.'
  desc 'check', 'If web administration is performed at the console, this check is Not Applicable.

If web administration is performed remotely the following checks will apply.

If administration of the server is performed remotely, it will only be performed securely by system administrators.

If website administration or web application administration has been delegated, those users will be documented and approved by the ISSO.

Remote administration must be in compliance with any requirements contained within the Windows Server STIGs, and any applicable network STIGs.

Remote administration of any kind will be restricted to documented and authorized personnel.

All users performing remote administration must be authenticated.

All remote sessions will be encrypted and they will utilize FIPS 140-2-approved protocols.

FIPS 140-2-approved TLS versions include TLS V1.2 or greater.

Review with site management how remote administration, if applicable, is configured on the website.

If remote management meets the criteria listed above, this is not a finding.

If remote management is utilized and does not meet the criteria listed above, this is a finding.'
  desc 'fix', 'Ensure the web server administration is only performed over a secure path.'
  impact 0.7
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15636r505366_chk'
  tag severity: 'high'
  tag gid: 'V-214426'
  tag rid: 'SV-214426r508658_rule'
  tag stig_id: 'IISW-SV-000141'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-15634r505367_fix'
  tag 'documentable'
  tag legacy: ['SV-91435', 'V-76739']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end

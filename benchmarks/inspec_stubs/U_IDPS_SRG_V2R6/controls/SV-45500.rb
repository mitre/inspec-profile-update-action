control 'SV-45500' do
  title 'The IDPS must be configured to remove or disable non-essential features, functions, and services of the IDPS application.'
  desc 'An IDPS can be capable of providing a wide variety of capabilities. Not all of these capabilities are necessary. Unnecessary services, functions, and applications increase the attack surface (sum of attack vectors) of a system. These unnecessary capabilities are often overlooked and therefore may remain unsecured.

This requirement applies to unnecessary features of the IDPS application itself.'
  desc 'check', 'Verify the IDPS is configured to remove or disable non-essential features, functions, and services of the IDPS application.

If the IDPS is not configured to remove or disable non-essential features, functions, and services of the IDPS application, this is a finding.'
  desc 'fix', 'Configure the IDPS to remove or disable non-essential features, functions, and services of the IDPS application.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42849r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34625'
  tag rid: 'SV-45500r2_rule'
  tag stig_id: 'SRG-NET-000131-IDPS-00097'
  tag gtitle: 'SRG-NET-000131-IDPS-00097'
  tag fix_id: 'F-38897r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-37507' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) from RedHat.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-4689'
  tag rid: 'SV-37507r2_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'GEN004600'
  tag fix_id: 'F-31417r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end

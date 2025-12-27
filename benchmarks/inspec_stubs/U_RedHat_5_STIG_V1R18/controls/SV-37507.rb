control 'SV-37507' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', 'Determine the version of the SMTP service software.

Procedure:
#rpm -q sendmail
RedHat sendmail 8.13.8-8 is the latest required version.
If the RedHat sendmail is installed and the version is not at least 8.13.8-8, this is a finding.

#rpm -q postfix
RedHat postfix-2.3.3-6-el5 is the latest required version.
If the postfix is installed and the version is not at least postfix-2.3.3-6-el5, this is a finding.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) from RedHat.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36166r2_chk'
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

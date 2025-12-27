control 'SV-45869' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', 'Determine the version of the SMTP service software.

Procedure:
#rpm -q sendmail
SUSE sendmail 8.14.3-50.20.1is the latest required version.
If SUSE sendmail is installed and the version is not at least8.14.3.-50.20.1, this is a finding.

#rpm -q postfix
SUSE postfix-2.5.6-5.8.1 is the latest required version.
If postfix is installed and the version is not at least2.5.6-5.8.1, this is a finding.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) fromNovell.'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43186r1_chk'
  tag severity: 'high'
  tag gid: 'V-4689'
  tag rid: 'SV-45869r1_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'GEN004600'
  tag fix_id: 'F-39247r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end

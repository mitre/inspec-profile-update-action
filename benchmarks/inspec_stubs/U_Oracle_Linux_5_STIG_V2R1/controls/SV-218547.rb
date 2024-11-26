control 'SV-218547' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', 'Determine the version of the SMTP service software.

Procedure:
#  rpm -q sendmail

sendmail-8.13.8-10 is the latest required version.  If sendmail is installed and the version is not at least 8.13.8-10, this is a finding.

# rpm -q postfix

postfix-2.3.3-7.el5 is the latest required version.  If the postfix is installed and the version is not at least 2:2.3.3-7, this is a finding.'
  desc 'fix', 'Obtain and install a newer version of the SMTP service software (sendmail or Postfix) from the operating system vendor.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20022r555839_chk'
  tag severity: 'high'
  tag gid: 'V-218547'
  tag rid: 'SV-218547r603259_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20020r555840_fix'
  tag 'documentable'
  tag legacy: ['V-4689', 'SV-62907']
  tag cci: ['CCI-000366', 'CCI-001230']
  tag nist: ['CM-6 b', 'SI-2 d']
end

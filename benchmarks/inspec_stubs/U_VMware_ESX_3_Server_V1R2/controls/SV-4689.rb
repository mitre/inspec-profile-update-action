control 'SV-4689' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', "Determine the version of the SMTP service software.

Locate the Sendmail daemon.
Procedure:
# find / -name sendmail

Obtain version information for the Sendmail daemon.
Procedure:
# what <file location>
OR
# strings <file location> | grep version

Version 8.14.4 is the latest required version.

If the Sendmail version is not at least 8.14.4 or the vendor's latest version, this is a finding."
  desc 'fix', 'Obtain and install a newer version of Sendmail from the operating system vendor or from http://www.sendmail.org or ftp://ftp.cs.berkeley.edu/ucb/sendmail.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-627r2_chk'
  tag severity: 'high'
  tag gid: 'V-4689'
  tag rid: 'SV-4689r2_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'GEN004600'
  tag fix_id: 'F-4617r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'VIVM-1'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end

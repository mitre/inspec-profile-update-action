control 'SV-35065' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', "Determine the version of the SMTP service software. To obtain version information for the Sendmail daemon:
# what /usr/sbin/sendmail
OR
# strings /usr/sbin/sendmail | grep -i version 

If the Sendmail version is not at least 8.14.4, or if it is not the vendor's latest version, this is a finding."
  desc 'fix', 'Obtain and install a newer version of Sendmail from the operating system vendor or from http://www.sendmail.org or ftp://ftp.cs.berkeley.edu/ucb/sendmail.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36572r2_chk'
  tag severity: 'high'
  tag gid: 'V-4689'
  tag rid: 'SV-35065r2_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'GEN004600'
  tag fix_id: 'F-31940r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end

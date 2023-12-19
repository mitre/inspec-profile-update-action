control 'SV-220049' do
  title 'The SMTP service must be an up-to-date version.'
  desc 'The SMTP service version on the system must be current to avoid exposing vulnerabilities present in unpatched versions.'
  desc 'check', "Determine the version of the SMTP service software, using a non-privileged account.
$ /usr/lib/sendmail -d0 -bt < /dev/null
(Note:  While this command will report the sendmail version almost immediately, it will take several moments to return to the shell prompt.  Press ctrl-C to terminate the sendmail process.)

Version 8.14.4 is the latest required version.
Version 8.14.4+Sun is available from Oracle for Solaris.

If the sendmail version is not at least 8.14.4 or Oracle's latest version, this is a finding."
  desc 'fix', 'Obtain and install the latest version of Sendmail from Oracle through normal software update processes, as implemented locally.'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21758r485141_chk'
  tag severity: 'high'
  tag gid: 'V-220049'
  tag rid: 'SV-220049r603265_rule'
  tag stig_id: 'GEN004600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21757r485142_fix'
  tag 'documentable'
  tag legacy: ['SV-39819', 'V-4689']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

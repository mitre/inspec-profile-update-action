control 'SV-215417' do
  title 'The SMTP service HELP command must not be enabled on AIX.'
  desc 'The HELP command should be disabled to mask version information. The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Run the following command to get the "HELP" file location:
# grep "^O HelpFile" /etc/mail/sendmail.cf

The above command should yield the following output:
O HelpFile=/etc/mail/helpfile

If the above command does not yield any output, this is not a finding.

The "HELP" file should be referenced by the "HelpFile" option.
 
Check to see if the "HELP" file exists:
# ls <helpfile_path>

If the "HELP" file exists, this is a finding.'
  desc 'fix', 'To disable the SMTP service HELP command remove the HELP file using command:
# rm <helpfile_path>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16615r294702_chk'
  tag severity: 'medium'
  tag gid: 'V-215417'
  tag rid: 'SV-215417r508663_rule'
  tag stig_id: 'AIX7-00-003122'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16613r294703_fix'
  tag 'documentable'
  tag legacy: ['SV-101773', 'V-91675']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

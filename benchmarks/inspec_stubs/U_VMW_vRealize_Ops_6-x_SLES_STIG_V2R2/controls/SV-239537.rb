control 'SV-239537' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information. The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check the permissions of the sendmail helpfile:

ls -al /usr/lib/sendmail.d/helpfile

If the permissions are not "0000", this is a finding.'
  desc 'fix', 'Run the following command to disable the sendmail helpfile:

# chmod 0000 /usr/lib/sendmail.d/helpfile'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42770r662060_chk'
  tag severity: 'medium'
  tag gid: 'V-239537'
  tag rid: 'SV-239537r662062_rule'
  tag stig_id: 'VROM-SL-000590'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42729r662061_fix'
  tag 'documentable'
  tag legacy: ['SV-99195', 'V-88545']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

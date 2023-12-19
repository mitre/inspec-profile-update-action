control 'SV-240443' do
  title 'The SMTP service HELP command must not be enabled.'
  desc 'The HELP command should be disabled to mask version information. The version of the SMTP service software could be used by attackers to target vulnerabilities present in specific software versions.'
  desc 'check', 'Check the permissions of the sendmail helpfile:

ls -al /usr/lib/sendmail.d/helpfile

If the permissions are not "0000", this is a finding.'
  desc 'fix', 'Run the following command to disable the sendmail helpfile:

# chmod 0000 /usr/lib/sendmail.d/helpfile'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43676r671068_chk'
  tag severity: 'medium'
  tag gid: 'V-240443'
  tag rid: 'SV-240443r671070_rule'
  tag stig_id: 'VRAU-SL-000610'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43635r671069_fix'
  tag 'documentable'
  tag legacy: ['SV-100313', 'V-89663']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

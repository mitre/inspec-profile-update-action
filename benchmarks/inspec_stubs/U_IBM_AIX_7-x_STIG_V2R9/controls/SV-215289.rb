control 'SV-215289' do
  title 'The AIX SSH server must use SSH Protocol 2.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.'
  desc 'check', 'From the command prompt, run the following command:
# grep ^Protocol /etc/ssh/sshd_config

The above command should yield the following output:
Protocol 2

If the above command does not show the ssh server supporting "Protocol 2" only, this is a finding.'
  desc 'fix', 'Add or edit the following line in the "/etc/ssh/sshd_config" file to support "Protocol 2" only:
Protocol 2

Save the change to /etc/ssh/sshd_config

Restart ssh daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16487r294318_chk'
  tag severity: 'medium'
  tag gid: 'V-215289'
  tag rid: 'SV-215289r877398_rule'
  tag stig_id: 'AIX7-00-002104'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-16485r294319_fix'
  tag 'documentable'
  tag legacy: ['SV-101345', 'V-91245']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

control 'SV-215402' do
  title 'The AIX SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.'
  desc 'check', "Check the SSH daemon configuration for allowed ciphers by running the following command: 
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#' 

The above command should yield the following output:
Ciphers aes128-ctr,aes192-ctr,aes256-ctr

If any of the following conditions are true, this is a finding.
1. No line is returned (default ciphers);
2. The returned ciphers list contains any cipher not starting with aes;
3. The returned ciphers list contains any cipher ending with cbc."
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file and add or edit a "Ciphers" line like this:
Ciphers aes128-ctr,aes192-ctr,aes256-ctr

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16600r294657_chk'
  tag severity: 'medium'
  tag gid: 'V-215402'
  tag rid: 'SV-215402r508663_rule'
  tag stig_id: 'AIX7-00-003100'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-16598r294658_fix'
  tag 'documentable'
  tag legacy: ['SV-101343', 'V-91243']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

control 'SV-254125' do
  title 'Nutanix AOS must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

'
  desc 'check', 'Inspect the "Ciphers" configuration with the following command:

$ sudo grep -i ciphers /etc/ssh/sshd_config
Ciphers aes256-ctr

If any ciphers other than "aes256-ctr" are listed, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to use only DoD approved ciphers by running the following command.

$ sudo salt-call state.sls security/CVM/sshdCVM

The SSH service will need to be restarted for the changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57610r846461_chk'
  tag severity: 'high'
  tag gid: 'V-254125'
  tag rid: 'SV-254125r846463_rule'
  tag stig_id: 'NUTX-OS-000080'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-57561r846462_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000877', 'CCI-001453', 'CCI-002421', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)', 'MA-4 (6)']
end

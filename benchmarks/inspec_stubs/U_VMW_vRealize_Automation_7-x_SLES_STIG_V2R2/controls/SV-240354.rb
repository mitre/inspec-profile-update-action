control 'SV-240354' do
  title 'The SLES for vRealize must implement DoD-approved encryption to protect the confidentiality of remote access sessions - SSH Client.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.'
  desc 'check', %q(Check the SSH daemon configuration for DoD-approved encryption to protect the confidentiality of SSH remote connections by performing the following commands:

Check the "Ciphers" setting in the "ssh_config" file.
# grep -i Ciphers /etc/ssh/ssh_config  | grep -v '#' 

The output must contain either nothing or any number of the following algorithms:
aes256-ctr,aes128-ctr.

If the output contains an algorithm not listed above, this is a finding.

Expected Output:
Ciphers aes256-ctr,aes128-ctr)
  desc 'fix', 'Update the "Ciphers" directive with the following command: 

# sed -i "/^[^#]*Ciphers/ c\\Ciphers aes256-ctr,aes128-ctr" /etc/ssh/ssh_config

Save and close the file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43587r766908_chk'
  tag severity: 'medium'
  tag gid: 'V-240354'
  tag rid: 'SV-240354r877398_rule'
  tag stig_id: 'VRAU-SL-000080'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-43546r670802_fix'
  tag 'documentable'
  tag legacy: ['SV-100135', 'V-89485']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

control 'SV-240486' do
  title 'The SLES for vRealize must implement cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', %q(Check the SSH daemon configuration for DoD-approved encryption to protect the confidentiality of SSH remote connections by performing the following commands:

Check the "Ciphers" setting in the "sshd_config" file.

# grep -i Ciphers /etc/ssh/sshd_config  | grep -v '#' 

The output must contain either nothing or any number of the following algorithms:

aes128-ctr, aes256-ctr.

If the output contains an algorithm not listed above, this is a finding.

Expected Output:
Ciphers aes256-ctr,aes128-ctr)
  desc 'fix', 'Update the "Ciphers" directive with the following command: 

# sed -i "/^[^#]*Ciphers/ c\\Ciphers aes256-ctr,aes128-ctr" /etc/ssh/sshd_config

Save and close the file. 

Restart the sshd process: 

# service sshd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43719r671197_chk'
  tag severity: 'medium'
  tag gid: 'V-240486'
  tag rid: 'SV-240486r671199_rule'
  tag stig_id: 'VRAU-SL-000890'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-43678r671198_fix'
  tag 'documentable'
  tag legacy: ['SV-100399', 'V-89749']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end

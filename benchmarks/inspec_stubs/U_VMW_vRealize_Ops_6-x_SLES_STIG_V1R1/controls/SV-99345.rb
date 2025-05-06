control 'SV-99345' do
  title 'The SLES for vRealize must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered. 

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. 

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', %q(Check the SSH daemon configuration for DoD-approved encryption to protect the confidentiality of SSH remote connections by performing the following commands:

Check the Cipher setting in the "sshd_config" file.

# grep -i Ciphers /etc/ssh/sshd_config  | grep -v '#' 

The output must contain either none or any number of the following algorithms:

aes128-ctr, aes256-ctr.

If the output contains an algorithm not listed above, this is a finding.

Expected Output:
Ciphers aes256-ctr,aes128-ctr)
  desc 'fix', 'Update the Ciphers directive with the following command: 

# sed -i "/^[^#]*Ciphers/ c\\Ciphers aes256-ctr,aes128-ctr" /etc/ssh/sshd_config

Save and close the file. Restart the sshd process: 

# service sshd restart'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88387r1_chk'
  tag severity: 'high'
  tag gid: 'V-88695'
  tag rid: 'SV-99345r1_rule'
  tag stig_id: 'VROM-SL-001285'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-95437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

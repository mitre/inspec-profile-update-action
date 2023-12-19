control 'SV-239609' do
  title 'The SLES for vRealize must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications, when used for nonlocal maintenance sessions.'
  desc 'Privileged access contains control and configuration information and is particularly sensitive, so additional protections are necessary. This is maintained by using cryptographic mechanisms, such as a hash function or digital signature, to protect integrity. 

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the Internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. 

The SLES for vRealize can meet this requirement through leveraging a cryptographic module. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system (e.g., the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch).'
  desc 'check', %q(Check the SSH daemon configuration for DoD-approved encryption to protect the confidentiality of SSH remote connections by performing the following commands:

Check the Cipher setting in the "sshd_config" file.

# grep -i Ciphers /etc/ssh/sshd_config  | grep -v '#' 

The output must contain either none or any number of the following algorithms:

aes128-ctr, aes256-ctr.

If the output contains an algorithm not listed above, this is a finding.

Expected Output:
Ciphers aes256-ctr,aes128-ctr)
  desc 'fix', "Update the Ciphers directive with the following command: 

# sed -i '/^[^#]*Ciphers/ c\\Ciphers aes256-ctr,aes128-ctr' /etc/ssh/sshd_config

Save and close the file. Restart the sshd process: 

# service sshd restart"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42842r662276_chk'
  tag severity: 'medium'
  tag gid: 'V-239609'
  tag rid: 'SV-239609r662278_rule'
  tag stig_id: 'VROM-SL-001225'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-42801r662277_fix'
  tag 'documentable'
  tag legacy: ['SV-99339', 'V-88689']
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end

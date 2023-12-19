control 'SV-254217' do
  title 'Nutanix AOS must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Confirm Nutanix AOS is configured to store encrypted representation of passwords and that the encryption meets required standards.

$ sudo grep -i encrypt /etc/login.defs
ENCRYPT_METHOD SHA512

If the /etc/login.defs file does not contain the required output, this is a finding.

$ sudo grep -i sha512 /etc/libuser.conf
crypt_style = sha512

If the /etc/libuser.conf file does not contain the required output, this is a finding.'
  desc 'fix', 'Configure the required password encryption requirements by running the following command.

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57702r846737_chk'
  tag severity: 'high'
  tag gid: 'V-254217'
  tag rid: 'SV-254217r846739_rule'
  tag stig_id: 'NUTX-OS-001320'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-57653r846738_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

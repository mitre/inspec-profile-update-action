control 'SV-239496' do
  title 'The SLES for vRealize must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Check that the user account passwords are stored hashed using sha512 by running the following command:

# cat /etc/default/passwd | grep CRYPT=sha512

If "CRYPT=sha512" is not listed, this is a finding.'
  desc 'fix', "Ensure password are being encrypted with hash sha512 with the following command:

# echo 'CRYPT=sha512'>>/etc/default/passwd"
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42729r661937_chk'
  tag severity: 'high'
  tag gid: 'V-239496'
  tag rid: 'SV-239496r661939_rule'
  tag stig_id: 'VROM-SL-000365'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-42688r661938_fix'
  tag 'documentable'
  tag legacy: ['SV-99113', 'V-88463']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

control 'SV-240398' do
  title 'The SLES for vRealize must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Check that the user account passwords are stored hashed using sha512 by running the following command:

# more /etc/shadow

If the password hash does not begins with "$6$" for user accounts such as "root" or "admin", this is a finding.'
  desc 'fix', 'Reset the user password using the following command:

# passwd [user account]'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43631r670933_chk'
  tag severity: 'high'
  tag gid: 'V-240398'
  tag rid: 'SV-240398r670935_rule'
  tag stig_id: 'VRAU-SL-000365'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-43590r670934_fix'
  tag 'documentable'
  tag legacy: ['SV-100223', 'V-89573']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end

control 'SV-218643' do
  title 'The /etc/smbpasswd file must be owned by root.'
  desc 'If the "smbpasswd" file is not owned by root, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the "smbpasswd" file.

# ls -l /etc/samba/passdb.tdb /etc/samba/secrets.tdb

If the "smbpasswd"  file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the files maintained by smbpasswd.
For instance:
# chown root /etc/samba/passdb.tdb /etc/samba/secrets.tdb'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20118r556127_chk'
  tag severity: 'medium'
  tag gid: 'V-218643'
  tag rid: 'SV-218643r603259_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20116r556128_fix'
  tag 'documentable'
  tag legacy: ['V-1029', 'SV-64077']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

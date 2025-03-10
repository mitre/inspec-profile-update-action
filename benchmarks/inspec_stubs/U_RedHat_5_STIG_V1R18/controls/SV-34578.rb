control 'SV-34578' do
  title 'The system must not have the unnecessary "ftp" account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "ftp" accounts.

Procedure:
# rpm -q krb5-workstation
An ftp server is part of "krb5-workstation". If it is installed the "ftp" user is necessary and this is not a finding.

# rpm -q vsftp
If the "vsftp" ftp server is installed the "ftp" user is necessary and this is not a finding.

# grep ^ftp /etc/passwd
If this account exists and no ftp server is installed which requires it, this is a finding.'
  desc 'fix', 'Remove the "ftp" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27279'
  tag rid: 'SV-34578r1_rule'
  tag stig_id: 'GEN000290-4'
  tag gtitle: 'GEN000290-4'
  tag fix_id: 'F-33040r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
  tag cci: ['CCI-000012']
  tag nist: ['AC-2 j']
end

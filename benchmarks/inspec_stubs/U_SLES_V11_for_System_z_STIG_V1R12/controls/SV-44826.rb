control 'SV-44826' do
  title 'GIDs reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages.  If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', %q(Confirm all accounts with a GID of 499 and below are used by a system account. 

Procedure:
List all the users with a GID of 0-499.

# awk -F: '$4 <= 499 {printf "%15s:%4s\n", $1, $4}' /etc/passwd | sort -n -t: -k2

If a GID reserved for system accounts (0 - 499) is used by a non-system account, this is a finding.)
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 499).'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42298r1_chk'
  tag severity: 'medium'
  tag gid: 'V-780'
  tag rid: 'SV-44826r1_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'GEN000360'
  tag fix_id: 'F-38265r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

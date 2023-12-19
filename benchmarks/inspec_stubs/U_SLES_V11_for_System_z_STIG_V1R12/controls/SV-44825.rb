control 'SV-44825' do
  title 'UIDs reserved for system accounts must not be assigned to non-system accounts.'
  desc 'Reserved UIDs are typically used by system software packages.  If non-system accounts have UIDs in this range, they may conflict with system software, possibly leading to the user having permissions to modify system files.'
  desc 'check', %q(Check the UID assignments for all accounts.

# awk -F: '$3 <= 499 {printf "%15s:%4s\n", $1, $3}' /etc/passwd | sort -n -t: -k2
Confirm all accounts with a UID of 499 and below are used by a system account. If a UID reserved for system accounts (0 - 499) is used by a non-system account, then this is a finding.)
  desc 'fix', 'Change the UID numbers for non-system accounts with reserved UIDs (those less or equal to 499).'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42297r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11946'
  tag rid: 'SV-44825r1_rule'
  tag stig_id: 'GEN000340'
  tag gtitle: 'GEN000340'
  tag fix_id: 'F-38264r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-218365' do
  title 'The system must be checked weekly for unauthorized setuid files as well as unauthorized modification to authorized setuid files.'
  desc 'Files with the setuid bit set will allow anyone running these files to be temporarily assigned the UID of the file. While many system files depend on these attributes for proper operation, security problems can result if setuid is assigned to programs allowing reading and writing of files, or shell escapes.'
  desc 'check', 'Ask the SA for the weekly automated or manual process used to generate a list of setuid files on the system and compare it with the prior list.

If no such process is in place, this is a finding.

If a file integrity tool is configured to monitor setuid files weekly, this is not a finding.

Review the process.

If the process does not identify and report changes in setuid files, this is a finding.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of suid files on the system and compare it with the prior list.

To create a list of suid files:

# find / -perm -4000 > suid-file-list

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19840r569053_chk'
  tag severity: 'medium'
  tag gid: 'V-218365'
  tag rid: 'SV-218365r603259_rule'
  tag stig_id: 'GEN002400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19838r569054_fix'
  tag 'documentable'
  tag legacy: ['V-803', 'SV-63421']
  tag cci: ['CCI-000366', 'CCI-000318']
  tag nist: ['CM-6 b', 'CM-3 f']
end

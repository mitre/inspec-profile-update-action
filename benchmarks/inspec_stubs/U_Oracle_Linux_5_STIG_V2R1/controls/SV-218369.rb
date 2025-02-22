control 'SV-218369' do
  title 'The system must be checked weekly for unauthorized setgid files as well as unauthorized modification to authorized setgid files.'
  desc 'Files with the setgid bit set will allow anyone running these files to be temporarily assigned the group id of the file. While many system files depend on these attributes for proper operation, security problems can result if setgid is assigned to programs allowing reading and writing of files, or shell escapes.'
  desc 'check', 'Ask the SA if a weekly automated or manual process is used to generate a list of setgid files on the system and compare it with the prior list.

If no such process is in place, this is a finding. 

If a file integrity tool is configured to monitor setgid files weekly, this is not a finding.

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  desc 'fix', 'Establish a weekly automated or manual process to generate a list of setgid files on the system and compare it with the prior list.

To create a list of setgid files:

# find / -perm -2000 > setgid-file-list

NOTE: The frequency may be increased to daily, if necessary, in accordance with the contingency plan.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19844r569065_chk'
  tag severity: 'medium'
  tag gid: 'V-218369'
  tag rid: 'SV-218369r603259_rule'
  tag stig_id: 'GEN002460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19842r569066_fix'
  tag 'documentable'
  tag legacy: ['V-804', 'SV-63589']
  tag cci: ['CCI-000366', 'CCI-000318']
  tag nist: ['CM-6 b', 'CM-3 f']
end

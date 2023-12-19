control 'SV-29471' do
  title 'File-auditing configuration does not meet minimum requirements.'
  desc 'Improper modification of the core system files can render a system inoperable.  Further, modifications to these system files can have a significant impact on the security configuration of the system.  Auditing of significant modifications made to the system files provides a method of determining the responsible party.'
  desc 'check', 'If system-level auditing is not enabled, or if the system and data partitions are not installed on NTFS partitions, then mark this as a finding.

Open Windows Explorer and use the file and folder properties function to verify that the audit settings on each partition/drive is configured to audit all "failures" for the "Everyone" group.

If any partition/drive is not configured to at least the minimum requirement, then this is a finding.'
  desc 'fix', 'Configure auditing on each partition/drive to audit all "Failures" for the "Everyone" group.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-23r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1080'
  tag rid: 'SV-29471r1_rule'
  tag gtitle: 'File Auditing Configuration'
  tag fix_id: 'F-52r1_fix'
  tag false_positives: 'Automated checking sometimes reports this as a false finding.  If a manual review of a questionable finding shows auditing to be set correctly, then this would not be a finding.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end

control 'SV-29471' do
  title 'File-auditing configuration does not meet minimum requirements.'
  desc 'Improper modification of the core system files can render a system inoperable.  Further, modifications to these system files can have a significant impact on the security configuration of the system.  Auditing of significant modifications made to the system files provides a method of determining the responsible party.'
  desc 'fix', 'Configure auditing on each partition/drive to audit all "Failures" for the "Everyone" group.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1080'
  tag rid: 'SV-29471r1_rule'
  tag gtitle: 'File Auditing Configuration'
  tag fix_id: 'F-52r1_fix'
  tag false_positives: 'Automated checking sometimes reports this as a false finding.  If a manual review of a questionable finding shows auditing to be set correctly, then this would not be a finding.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-3, ECAR-1, ECAR-2'
end

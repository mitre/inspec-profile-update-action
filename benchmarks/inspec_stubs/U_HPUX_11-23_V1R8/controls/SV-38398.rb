control 'SV-38398' do
  title 'A root kit check tool must be run on the system at least weekly.'
  desc 'Root kits are software packages designed to conceal the compromise of a system from the SA. Root kit checking tools examine a system for evidence of an installed root kit. Dedicated root kit detection software or root kit detection capabilities included in anti-virus packages may be used to satisfy this requirement.'
  desc 'check', 'Ask the SA if a root kit check tool is installed on the system and run weekly.  Verify this is the case by checking software inventory and automated job-scheduling tools, such as cron.  Some root kit check tools may run from read-only alternate boot media, requiring several reboots of the system.

If a root kit check tool not requiring a system reboot is not run at least weekly, either via manual or automated means, this is a finding.

If a root kit check tool requiring a system reboot is not run at regular intervals less frequent than weekly, but at least every 30 days, this is a finding.'
  desc 'fix', 'Create an automated job or establish a site-defined procedure to check the system weekly with a root kit check tool.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36785r5_chk'
  tag severity: 'medium'
  tag gid: 'V-22575'
  tag rid: 'SV-38398r1_rule'
  tag stig_id: 'GEN008380'
  tag gtitle: 'GEN008380'
  tag fix_id: 'F-32165r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

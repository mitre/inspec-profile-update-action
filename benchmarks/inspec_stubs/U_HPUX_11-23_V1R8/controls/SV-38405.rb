control 'SV-38405' do
  title 'The system package management tool must not automatically obtain updates.'
  desc "System package management tools can obtain a list of updates and patches from a package repository and make this information available to the SA for review and action. Using a package repository outside of the organization's control presents a risk that malicious packages could be introduced."
  desc 'check', 'Determine if the system package management tool is configured to automatically obtain updated packages. If it is, this is a finding.

SWA runs as a client-side patch and security analysis tool. An HP supplied catalog file with known problems and fixes is downloaded from the HP IT Resource Center (ITRC) and compared to the software installed on the system. Depots used for full-system installation, such as the installation depot on an OE DVD, may also be analyzed. Systems are analyzed for patch warnings, critical defects, security bulletins, missing Quality Pack (QPK) patch bundles, and user-specified patches and supersession chains. SWA optimizes the automatic selection of patch dependencies by assessing the quality of the dependency, providing the best case scenario for the dependency, minimizing changes to the system, and assessing future patch dependency changes. 

List all crontabs on the system. 
# ls -lL /var/spool/cron/crontabs/*
# ls -lL /var/spool/cron/atjobs/*

Check all crontabs/atjobs on the system for swa entries.
# cat /var/spool/cron/crontabs/* | grep "swa "
# cat /var/spool/cron/atjobs/* | grep "swa "

If SWA is not configured with cron or at, this is not a finding.'
  desc 'fix', 'Configure the system package management tool to not automatically obtain updates.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36802r1_chk'
  tag severity: 'low'
  tag gid: 'V-22589'
  tag rid: 'SV-38405r1_rule'
  tag stig_id: 'GEN008820'
  tag gtitle: 'GEN008820'
  tag fix_id: 'F-32179r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end

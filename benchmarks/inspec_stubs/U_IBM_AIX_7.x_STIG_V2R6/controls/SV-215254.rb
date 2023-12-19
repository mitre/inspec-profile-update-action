control 'SV-215254' do
  title 'AIX must provide a report generation function that supports on-demand audit review and analysis, on-demand reporting requirements, and after-the-fact investigations of security incidents.'
  desc "The report generation capability must support on-demand review and analysis in order to facilitate the organization's ability to generate incident reports, as needed, to better handle larger-scale or more complex security incidents. If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Report generation must be capable of generating on-demand (i.e., customizable, ad hoc, and as-needed) reports. On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective.

"
  desc 'check', 'Check to see if the application for generating audit reports exists ("/usr/sbin/auditpr"):

# ls -l /usr/sbin/auditpr
-r-sr-x---    1 root     audit         54793 Feb 14 2017  /usr/sbin/auditpr

If the file does not exist, this is a finding.'
  desc 'fix', 'Use the  installp command to install a fileset (assume cd is mounted).
# installp -aXYqg -d /dev/cd0 bos.rte.security'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16452r294213_chk'
  tag severity: 'medium'
  tag gid: 'V-215254'
  tag rid: 'SV-215254r508663_rule'
  tag stig_id: 'AIX7-00-002036'
  tag gtitle: 'SRG-OS-000350-GPOS-00138'
  tag fix_id: 'F-16450r294214_fix'
  tag satisfies: ['SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140']
  tag 'documentable'
  tag legacy: ['V-91521', 'SV-101619']
  tag cci: ['CCI-001878', 'CCI-001879', 'CCI-001880']
  tag nist: ['AU-7 a', 'AU-7 a', 'AU-7 a']
end

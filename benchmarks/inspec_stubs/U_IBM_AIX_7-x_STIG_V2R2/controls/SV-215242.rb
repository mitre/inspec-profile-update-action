control 'SV-215242' do
  title 'AIX must provide the function to filter audit records for events of interest based upon all audit fields within audit records, support on-demand reporting requirements, and an audit reduction function that supports on-demand audit review and analysis and after-the-fact investigations of security incidents.'
  desc "The ability to specify the event criteria that are of interest provides the individuals reviewing the logs with the ability to quickly isolate and identify these events without having to review entries that are of little or no consequence to the investigation. Without this capability, forensic investigations are impeded.

Events of interest can be identified by the content of specific audit record fields, including, for example, identities of individuals, event types, event locations, event times, event dates, system resources involved, IP addresses involved, or information objects accessed. Organizations may define audit event criteria to any degree of granularity required, for example, locations selectable by general networking location (e.g., by network or subnetwork) or selectable by specific information system component.

The ability to generate on-demand reports, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents.

The ability to perform on-demand audit review and analysis, including after the audit data has been subjected to audit reduction, greatly facilitates the organization's ability to generate incident reports, as needed, to better handle larger-scale or more complex security incidents. If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction is a process that manipulates collected audit information and organizes such information in a summary format that is more meaningful to analysts. The report generation capability provided by the application must support on-demand (i.e., customizable, ad hoc, and as-needed) reports.

This requires operating systems to provide the capability to customize audit record reports based on all available criteria.

"
  desc 'check', 'The application file "/usr/sbin/auditselect" provides the audit filtering function. Check if it exists:

#  ls -l /usr/sbin/auditselect
-r-sr-x---    1 root     audit         36240 Jul 4 1776  /usr/sbin/auditselect

If the  "/usr/sbin/auditselect" file does not exist, this is a finding'
  desc 'fix', 'Re-install the "bos.rte.security" fileset from the base media.

Use "installp" command (assume cd is mounted).

# installp -aXYqg -d /dev/cd0 bos.rte.security'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16440r294177_chk'
  tag severity: 'medium'
  tag gid: 'V-215242'
  tag rid: 'SV-215242r517599_rule'
  tag stig_id: 'AIX7-00-002011'
  tag gtitle: 'SRG-OS-000054-GPOS-00025'
  tag fix_id: 'F-16438r294178_fix'
  tag satisfies: ['SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137']
  tag 'documentable'
  tag legacy: ['SV-101359', 'V-91259']
  tag cci: ['CCI-000158', 'CCI-001875', 'CCI-001876', 'CCI-001877']
  tag nist: ['AU-7 (1)', 'AU-7 a', 'AU-7 a', 'AU-7 a']
end

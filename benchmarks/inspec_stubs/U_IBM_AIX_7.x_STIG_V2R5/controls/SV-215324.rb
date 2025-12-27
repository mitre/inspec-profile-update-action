control 'SV-215324' do
  title 'AIX log files must not have extended ACLs, except as needed to support authorized software.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify AIX or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(With the assistance of the system administrator, identify all of the system log files.

For each system log file identified, verify that extended ACL's are disabled:

#aclget <system_log_file>
*
* ACL_type   AIXC
*
attributes:
base permissions
    owner(root):  rw-
    group(system):  r--
    others:  r--
extended permissions
    disabled

If "extended permissions" is set to "enabled" and is not documented, this is a finding.)
  desc 'fix', 'Remove the extended ACL(s) from the system log file(s):
# acledit <system_log_file>

Set "extended permissions" to "disabled".'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16522r294423_chk'
  tag severity: 'medium'
  tag gid: 'V-215324'
  tag rid: 'SV-215324r508663_rule'
  tag stig_id: 'AIX7-00-003007'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-16520r294424_fix'
  tag 'documentable'
  tag legacy: ['V-91457', 'SV-101555']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

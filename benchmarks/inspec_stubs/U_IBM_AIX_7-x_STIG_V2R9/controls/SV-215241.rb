control 'SV-215241' do
  title 'AIX must be configured to generate an audit record when 75% of the audit file system is full.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Check if "freespace" is configured for the audit subsystem:

# grep -E freespace* /etc/security/audit/config 
freespace = 65536

If the above command returns empty, or if the value is less than 25% of the filesystem size, this is a finding.'
  desc 'fix', 'Ensure the "/etc/security/audit/config" file contains the following line:
freepsace = <value>
where <value> is greater than 25%* filesystem capacity

Reset the audit system with the following command:
# /usr/sbin/audit shutdown

Start the audit system with the following command:
# /usr/sbin/audit start'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16439r294174_chk'
  tag severity: 'medium'
  tag gid: 'V-215241'
  tag rid: 'SV-215241r508663_rule'
  tag stig_id: 'AIX7-00-002008'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-16437r294175_fix'
  tag 'documentable'
  tag legacy: ['V-91257', 'SV-101357']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

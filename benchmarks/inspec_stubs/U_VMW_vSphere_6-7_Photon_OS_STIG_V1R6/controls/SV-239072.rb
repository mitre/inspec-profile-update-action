control 'SV-239072' do
  title 'The Photon operating system must be configured to offload audit logs to a syslog server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-services-auditd.conf

Expected result:

input(type="imfile" File="/var/log/audit/audit.log"
Tag="auditd"
Severity="info"
Facility="local0")

If the file does not exist, this is a finding.

If the output of the command does not match the expected result above, this is a finding.'
  desc 'fix', 'Open /etc/vmware-syslog/stig-services-auditd.conf with a text editor.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile" File="/var/log/audit/audit.log"
Tag="auditd"
Severity="info"
Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42283r675022_chk'
  tag severity: 'medium'
  tag gid: 'V-239072'
  tag rid: 'SV-239072r877390_rule'
  tag stig_id: 'PHTN-67-000129'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-42242r840144_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001851', 'CCI-002702']
  tag nist: ['AU-4 (1)', 'SI-6 d']
end

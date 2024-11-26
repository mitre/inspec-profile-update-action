control 'SV-258837' do
  title 'The Photon operating system must protect audit tools from unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'At the command line, run the following command to verify permissions on audit tools:

# stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/audispd /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace /usr/sbin/augenrules

Expected result:

/usr/sbin/audispd is owned by root and group owned by root and permissions are 750
/usr/sbin/auditctl is owned by root and group owned by root and permissions are 755
/usr/sbin/auditd is owned by root and group owned by root and permissions are 755
/usr/sbin/aureport is owned by root and group owned by root and permissions are 755
/usr/sbin/ausearch is owned by root and group owned by root and permissions are 755
/usr/sbin/autrace is owned by root and group owned by root and permissions are 755
/usr/sbin/augenrules is owned by root and group owned by root and permissions are 750

If any file is not owned by root or group owned by root or permissions are more permissive than listed above, this is a finding.'
  desc 'fix', 'At the command line, run the following commands for each file returned:

# chown root:root <file>
# chmod 750 <file>

Note: Update permissions to match the target file as listed in the check text.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62577r933570_chk'
  tag severity: 'medium'
  tag gid: 'V-258837'
  tag rid: 'SV-258837r933572_rule'
  tag stig_id: 'PHTN-40-000082'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-62486r933571_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end

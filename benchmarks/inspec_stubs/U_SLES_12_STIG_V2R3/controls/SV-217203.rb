control 'SV-217203' do
  title 'The SUSE operating system audit tools must have the proper permissions configured to protect against unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

SUSE operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the access to audit tools.

Audit tools include but are not limited to vendor-provided and open-source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify that the SUSE operating system audit tools have the proper permissions configured in the permissions profile to protect from unauthorized access.

Check that "permissions.local" file contains the correct permissions rules with the following command:

> grep "^/usr/sbin/au" /etc/permissions.local

/usr/sbin/audispd root:root 0750
/usr/sbin/auditctl root:root 0750
/usr/sbin/auditd root:root 0750
/usr/sbin/ausearch root:root 0755
/usr/sbin/aureport root:root 0755
/usr/sbin/autrace root:root 0750
/usr/sbin/augenrules root:root 0750

If the command does not return any output, this is a finding.

Check that all of the audit information files and folders have the correct permissions with the following command:

> sudo chkstat /etc/permissions.local

If the command returns any output, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system audit tools to have with proper permissions set in the permissions profile to protect from unauthorized access.

Edit the file "/etc/permissions.local" and insert the following text:

/usr/sbin/audispd       root:root 0750
/usr/sbin/auditctl      root:root 0750
/usr/sbin/auditd        root:root 0750
/usr/sbin/ausearch      root:root 0755
/usr/sbin/aureport      root:root 0755
/usr/sbin/autrace       root:root 0750
/usr/sbin/augenrules    root:root 0750

Set the correct permissions with the following command:

> sudo chkstat --set /etc/permissions.local'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18431r646741_chk'
  tag severity: 'medium'
  tag gid: 'V-217203'
  tag rid: 'SV-217203r646743_rule'
  tag stig_id: 'SLES-12-020130'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-18429r646742_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag legacy: ['V-77313', 'SV-92009']
  tag cci: ['CCI-001494', 'CCI-001495', 'CCI-001493']
  tag nist: ['AU-9', 'AU-9', 'AU-9 a']
end

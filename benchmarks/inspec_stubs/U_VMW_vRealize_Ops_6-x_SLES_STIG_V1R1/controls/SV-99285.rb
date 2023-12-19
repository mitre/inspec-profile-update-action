control 'SV-99285' do
  title 'The SLES for vRealize must protect audit tools from unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

SLES for vRealize systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(The following command will list which audit files on the system have permissions different from what is expected by the RPM database: 

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by the RPM database, this is a finding.)
  desc 'fix', 'For each file that has permissions that are more permissive than those expected by the RPM database, alter the permission of the file with the following command:

# chmod <permission> <filename>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88635'
  tag rid: 'SV-99285r1_rule'
  tag stig_id: 'VROM-SL-000880'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-95377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

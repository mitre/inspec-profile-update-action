control 'SV-240489' do
  title 'The SLES for vRealize must protect audit tools from unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', %q(The following command will list which audit files on the system have permissions different from what is expected by the RPM database: 

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.)
  desc 'fix', 'Run the following command to reset audit permissions to the correct values:

sudo rpm --setperms audit-1.8-0.34.26'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43722r671206_chk'
  tag severity: 'medium'
  tag gid: 'V-240489'
  tag rid: 'SV-240489r671208_rule'
  tag stig_id: 'VRAU-SL-000905'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-43681r671207_fix'
  tag 'documentable'
  tag legacy: ['SV-100405', 'V-89755']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

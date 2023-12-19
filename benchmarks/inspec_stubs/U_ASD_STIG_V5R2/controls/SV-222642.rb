control 'SV-222642' do
  title 'The application must not contain embedded authentication data.'
  desc 'Authentication data stored in code could potentially be read and used by anonymous users to gain access to a backend database or application servers. This could lead to compromise of application data.'
  desc 'check', 'Review the application documentation and any available source code; this includes configuration files such as global.asa, if present, scripts, HTML files, and any ASCII files.

Identify any instances of passwords, certificates, or sensitive data included in code.

If credentials were found, check the file permissions and ownership of the offending file.

If access to the folder hosting the file is not restricted to the related application process and administrative users, this is a finding.

The finding details should note specifically where the offending credentials or data were located and what resources they enabled.'
  desc 'fix', 'Remove embedded authentication data stored in code, configuration files, scripts, HTML file, or any ASCII files.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24312r493834_chk'
  tag severity: 'high'
  tag gid: 'V-222642'
  tag rid: 'SV-222642r849509_rule'
  tag stig_id: 'APSC-DV-003110'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24301r493835_fix'
  tag 'documentable'
  tag legacy: ['SV-84985', 'V-70363']
  tag cci: ['CCI-002367']
  tag nist: ['IA-5 (7)']
end

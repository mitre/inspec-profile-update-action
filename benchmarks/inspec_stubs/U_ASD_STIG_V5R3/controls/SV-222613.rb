control 'SV-222613' do
  title 'The application must remove organization-defined software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Review the application documentation and interview the application admin to identify application locations on system.

Identify application versions that are installed on the system.

Review the file system structure to see if older versions of the application are still installed.

If old versions of the application or components are still installed on the system, this is a finding.'
  desc 'fix', 'Configure or design the application to remove old components when updating.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24283r493747_chk'
  tag severity: 'medium'
  tag gid: 'V-222613'
  tag rid: 'SV-222613r879825_rule'
  tag stig_id: 'APSC-DV-002610'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-24272r493748_fix'
  tag 'documentable'
  tag legacy: ['SV-84901', 'V-70279']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end

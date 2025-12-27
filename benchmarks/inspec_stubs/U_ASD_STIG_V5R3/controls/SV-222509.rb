control 'SV-222509' do
  title 'The integrity of the audit tools must be validated by checking the files for changes in the cryptographic hash value.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step to ensuring the integrity of audit data. Audit data includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs. 

To address this risk, audit tools must be cryptographically signed/hashed in order to provide the capability to identify when the audit tools have been modified, manipulated or replaced. An example is a checksum hash of the file or files.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods, and provided audit tools.

Identify the location of the application audit tools.

Separate audit tools will be file-oriented in nature, e.g., the application includes a separate executable file or library that when invoked allows users to view and manipulate logs.

If the application does not provide a separate tool in the form of a file which provides an ability to view and manipulate application log data, query data or generate reports, this requirement is not applicable.

If the system hosting the application has a separate file monitoring utility installed that is configured to identify changes to audit tools and alarm on changes to audit tools, this is not applicable.

Ask the application administrator to provide their process for periodically checking the list of checksum values against the associated file names of the audit tools to ensure none of the audit tools have been tampered with.

If a cryptographic checksum or hash value of the audit tool file is not periodically checked to ensure the integrity of audit tools, this is a finding.'
  desc 'fix', 'Establish a process to periodically check the audit tool cryptographic hashes to ensure the audit tools have not been tampered with.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24179r493435_chk'
  tag severity: 'medium'
  tag gid: 'V-222509'
  tag rid: 'SV-222509r879668_rule'
  tag stig_id: 'APSC-DV-001370'
  tag gtitle: 'SRG-APP-000290'
  tag fix_id: 'F-24168r493436_fix'
  tag 'documentable'
  tag legacy: ['SV-84123', 'V-69501']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end

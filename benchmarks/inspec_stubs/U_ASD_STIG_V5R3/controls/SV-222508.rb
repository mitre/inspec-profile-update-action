control 'SV-222508' do
  title 'Application audit tools must be cryptographically hashed.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step to ensuring the integrity of audit data. Audit data includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed/hashed and the resulting value securely stored in order to provide the capability to identify when the audit tools have been modified, manipulated or replaced.

Some OSs provide a native command line tool capable of extracting or creating a hash value. Care must be taken to ensure any hashing algorithm strength used is acceptable.  An example is UNIX OS variants that provide the "shasum" utility with SHA256 capabilities.  Windows is not known to provide a native cryptographic tool that utilizes an acceptable hashing algorithm.  The Windows fciv.exe checksum tool currently only utilizes MD5 and SHA1 which are not acceptable hashing algorithms.'
  desc 'check', 'Review the system documentation and interview the application administrator for details regarding application architecture, audit methods, and provided audit tools.

Identify the location of the application audit tools.

Separate audit tools will be file-oriented in nature, e.g., the application includes a separate executable file or library that when invoked allows users to view and manipulate logs.

If the application does not provide a separate tool in the form of a file which provides an ability to view and manipulate application log data, query data, or generate reports, this requirement is not applicable.

If the system hosting the application has a separate file monitoring utility installed that is configured to identify changes to audit tools and alarm on changes to audit tools, this is not applicable.

Ask application administrator to demonstrate the cryptographic hashing mechanisms used to create the one way hashes that can be used to validate the integrity of audit tools.

For example, "shasum /path/to/file > checksum.filename".

Ask the application administrator to provide the list of checksum values and the associated file names of the audit tools.

If a cryptographic checksum or hash value of the audit tool file is not created for future reference, this is a finding.'
  desc 'fix', 'Cryptographically hash the audit tool files used by the application. Store and protect the generated hash values for future reference.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24178r493432_chk'
  tag severity: 'medium'
  tag gid: 'V-222508'
  tag rid: 'SV-222508r879668_rule'
  tag stig_id: 'APSC-DV-001360'
  tag gtitle: 'SRG-APP-000290'
  tag fix_id: 'F-24167r493433_fix'
  tag 'documentable'
  tag legacy: ['SV-84121', 'V-69499']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end

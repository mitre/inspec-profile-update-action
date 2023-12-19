control 'SV-252910' do
  title 'The version of Internet Explorer running on the system must be a supported version.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may depend on the Information Assurance Vulnerability Management (IAVM) process.'
  desc 'check', 'Internet Explorer 11 is no longer supported on Windows 10 semi-annual channel. If Internet Explorer 11 is installed or enabled on Windows 10 semi-annual channel, this is a finding.

If IE11 is installed or enabled on an unsupported OS, this is a finding.'
  desc 'fix', 'For Windows 10 semi-annual channel, remove or disable the IE11 application.

To disable IE11 as a standalone browser:

Set the policy value for "Computer Configuration/Administrative Templates/Windows Components/Internet Explorer/Disable Internet Explorer 11 as a standalone browser" to "Enabled" with the option value set to "Never".'
  impact 0.7
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-56363r870852_chk'
  tag severity: 'high'
  tag gid: 'V-252910'
  tag rid: 'SV-252910r870854_rule'
  tag stig_id: 'DTBI999-IE11'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-56313r870853_fix'
  tag 'documentable'
  tag cci: ['CCI-002635']
  tag nist: ['SI-3 (10) (a)']
end

control 'SV-213192' do
  title 'Adobe Reader DC must have the latest Security-related Software Updates installed.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Determine the method for doing this (e.g., connection to a WSUS server, local procedure, auto update, etc.).

Open Adobe Acrobat Reader DC.

Navigate to and click on Help >> About Adobe Acrobat Reader DC.

Verify that the latest security-related software updates by Adobe are being applied.

If the latest security-related software updates by Adobe are not being applied, this is a finding.'
  desc 'fix', 'Apply the latest security-related software updates to the Adobe Acrobat Reader application.'
  impact 0.7
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous Track'
  tag check_id: 'C-14427r276794_chk'
  tag severity: 'high'
  tag gid: 'V-213192'
  tag rid: 'SV-213192r400525_rule'
  tag stig_id: 'ARDC-CN-000340'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-14425r276795_fix'
  tag 'documentable'
  tag legacy: ['SV-80167', 'V-65677']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

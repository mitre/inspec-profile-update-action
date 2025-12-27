control 'SV-96115' do
  title 'The WebSphere Application Server must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVMs, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', 'From the admin console, click on "welcome".

Under Suite Name, locate "WebSphere Application Server".

View the "version". 

Access IBM support website: https://www.ibm.com/support

Identify the most recent patch/fix version available for the WebSphere Traditional Application Server (not the Liberty version).

If the most recent patches/fix packs have not been applied, this is a finding.'
  desc 'fix', 'Sign up to receive WebSphere security bulletins at the IBM website.

Monitor IAVMs, CTOs, and DTMs for update notices affecting WebSphere.

Obtain WebSphere product security and patch support.

Test and apply the latest applicable WebSphere security fixes.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81401'
  tag rid: 'SV-96115r1_rule'
  tag stig_id: 'WBSP-AS-001760'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-88187r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

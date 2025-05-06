control 'SV-240958' do
  title 'The vAMI must have security-relevant software updates installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if a local procedure exists to install security-relevant software updates in a satisfactory timeframe.

If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to install security-relevant software updates in a satisfactory timeframe.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44191r676039_chk'
  tag severity: 'medium'
  tag gid: 'V-240958'
  tag rid: 'SV-240958r879827_rule'
  tag stig_id: 'VRAU-VA-000595'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-44150r676040_fix'
  tag 'documentable'
  tag legacy: ['SV-100911', 'V-90261']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

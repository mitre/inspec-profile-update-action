control 'SV-89505' do
  title 'The MQ Appliance messaging server must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes) to production systems after thorough testing of the patches within a lab environment. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.'
  desc 'check', 'From the MQ Appliance CLI, enter the following command:

show version

If the displayed version does not correspond to the most recent organizationally approved available firmware update, this is a finding.'
  desc 'fix', 'Install the most recent organizationally proved firmware update available from the vendor.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74831'
  tag rid: 'SV-89505r1_rule'
  tag stig_id: 'MQMH-AS-000810'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-81447r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

control 'SV-214270' do
  title 'The Apache web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

The Apache web server will be configured to check for and install security-relevant software updates from an authoritative source within an identified time period from the availability of the update. By default, this time period will be every 24 hours.'
  desc 'check', 'Determine the most recent patch level of the Apache Web Server 2.4 software, as posted on the Apache HTTP Server Project website. If the Apache installation is a proprietary installation supporting an application and is supported by a vendor, determine the most recent patch level of the vendor’s installation.

In a command line, type "httpd -v".

If the version is more than one version behind the most recent patch level, this is a finding.'
  desc 'fix', 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15484r854710_chk'
  tag severity: 'medium'
  tag gid: 'V-214270'
  tag rid: 'SV-214270r879827_rule'
  tag stig_id: 'AS24-U1-000930'
  tag gtitle: 'SRG-APP-000456-WSR-000187'
  tag fix_id: 'F-15482r277071_fix'
  tag 'documentable'
  tag legacy: ['SV-102837', 'V-92749']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

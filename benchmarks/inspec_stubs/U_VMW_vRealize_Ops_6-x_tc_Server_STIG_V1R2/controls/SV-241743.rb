control 'SV-241743' do
  title 'tc Server ALL must have all security-relevant software updates installed within the configured time period directed by an authoritative source.'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

The web server will be configured to check for and install security-relevant software updates from an authoritative source within an identified time period from the availability of the update. By default, this time period will be every 24 hours.

VMware delivers product updates and patches regularly. It is crucial that system administrators coordinate installation of product updates with the site ISSO to ensure that updated and patched files are uploaded onto the system as soon as prescribed.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review the policies and procedures used to ensure that all security-related upgrades are being installed within the configured time period directed by an authoritative source.

If all security-related upgrades are not being installed within the configured time period directed by an authoritative source, this is a finding.'
  desc 'fix', 'Ensure that patches and updates from an authoritative source are applied at least within 24 hours after they have been received.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45019r854973_chk'
  tag severity: 'medium'
  tag gid: 'V-241743'
  tag rid: 'SV-241743r879827_rule'
  tag stig_id: 'VROM-TC-001020'
  tag gtitle: 'SRG-APP-000456-WSR-000187'
  tag fix_id: 'F-44978r684090_fix'
  tag 'documentable'
  tag legacy: ['SV-99771', 'V-89121']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

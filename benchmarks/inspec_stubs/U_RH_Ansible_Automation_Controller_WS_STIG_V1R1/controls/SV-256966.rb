control 'SV-256966' do
  title 'Automation Controller NGINX web servers must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Red Hat constantly updates and patches Automation Controller to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

The Automation Controller NGINX web server will be configured to check for and install security-relevant software updates from an authoritative source within an organizationally identified time period from the availability of the update. By default, this time period will be every 24 hours.'
  desc 'check', 'As a System Administrator for each Automation Controller NGINX web server host, verify the system is configured to receive updates from an organizationally defined source for authoritative system updates:

yum -v repolist

If each URL is not valid and consistent with organizationally defined requirements, this is a finding.

If each repository is not enabled in accordance with organizationally defined requirements, this is a finding.

If the system is not configured to automatically receive and apply system updates from this source at least every 30 days, or manually receive and apply updates at least every 30 days, this is a finding.'
  desc 'fix', "As a system administrator, for each Automation Controller NGINX web server host, perform the following:

1. Either configure update repositories in accordance with organizationally defined requirements or subscribe to Red Hat update repositories for the underlying operating system.

2. Execute an update from these repositories:

$ yum update -y

3. Perform one of the following:

3.1. Schedule an update to occur every 30 days, or in accordance with organizationally defined policy:

$ yum install -y dnf-automatic  && sed -i '/apply_updates/s/no/yes/' /etc/dnf/automatic.conf && sed -i '/OnCalendar/s/^OnCalendar\\s*=.*/OnCalendar=*-1-* 6:00/' /usr/lib/systemd/system/dnf-automatic.timer && systemctl enable --now dnf-automatic.timer

3.2. Schedule manual updates to occur at least every 30 days, or in accordance with organizationally defined policy. 

4. Restart the Automation Controller NGINX web server host."
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60641r902410_chk'
  tag severity: 'medium'
  tag gid: 'V-256966'
  tag rid: 'SV-256966r903536_rule'
  tag stig_id: 'APWS-AT-000940'
  tag gtitle: 'SRG-APP-000456-WSR-000187'
  tag fix_id: 'F-60583r903536_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end

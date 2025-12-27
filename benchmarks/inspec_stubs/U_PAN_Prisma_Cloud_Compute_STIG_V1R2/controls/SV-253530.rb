control 'SV-253530' do
  title "Prisma Cloud Compute must be configured to send events to the hosts' syslog."
  desc "Event log collection is critical in ensuring the security of a containerized environment due to the ephemeral nature of the workloads. In an environment that is continually in flux, audit logs must be properly collected and secured. Prisma Cloud Compute can be configured to send audit events to the host node's syslog in RFC5424-compliant format.

"
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Alerts >> Logging tab. 

If the Syslog setting is "disabled", this is a finding.

Select the "Manage" tab.

If no Alert Providers are configured, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Alerts >> Logging tab. 

Set Syslog to "enabled".

Select the "Manage" tab.

Click "Add profile".

Complete the form based on the organization. At a minimum, the following Alert triggers must be selected:
- Host vulnerabilities.
- Image vulnerabilities.

Click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56982r840426_chk'
  tag severity: 'medium'
  tag gid: 'V-253530'
  tag rid: 'SV-253530r840428_rule'
  tag stig_id: 'CNTR-PC-000310'
  tag gtitle: 'SRG-APP-000111-CTR-000220'
  tag fix_id: 'F-56933r840427_fix'
  tag satisfies: ['SRG-APP-000111-CTR-000220', 'SRG-APP-000181-CTR-000485', 'SRG-APP-000358-CTR-000805', 'SRG-APP-000474-CTR-001180', 'SRG-APP-000516-CTR-000790']
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-000366', 'CCI-001851', 'CCI-001876', 'CCI-002702']
  tag nist: ['AU-6 (4)', 'CM-6 b', 'AU-4 (1)', 'AU-7 a', 'SI-6 d']
end

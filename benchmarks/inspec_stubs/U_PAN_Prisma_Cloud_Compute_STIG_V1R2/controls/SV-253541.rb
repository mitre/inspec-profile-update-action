control 'SV-253541' do
  title 'Prisma Cloud Compute must not write sensitive data to event logs.'
  desc 'The determination of what is sensitive data varies from organization to organization. The organization must ensure the recipients for the event log information have a need to know and the log is sanitized based on the audience.'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> General tab. 

Inspect the Log Scrubbing section. If "Automatically scrub secrets from runtime events" is "off", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> General tab. 

In the Log Scrubbing section, set "Automatically scrub secrets from runtime events" to "on" and click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56993r840459_chk'
  tag severity: 'medium'
  tag gid: 'V-253541'
  tag rid: 'SV-253541r840461_rule'
  tag stig_id: 'CNTR-PC-000880'
  tag gtitle: 'SRG-APP-000266-CTR-000625'
  tag fix_id: 'F-56944r840460_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end

control 'SV-253528' do
  title 'Prisma Cloud Compute must be configured for forensic data collection.'
  desc "Prisma Cloud Compute correlates raw audit data to actionable security intelligence, enabling a more rapid and effective response to incidents. This reduces the manual, time-consuming task of correlating data.

Prisma Cloud Forensics is a lightweight distributed data recorder that runs alongside all containers in the environment. Prisma Cloud continuously collects detailed runtime information to help incident response teams understand what happened before, during, and after a breach.

Forensic data consists of additional supplemental runtime events that complement the data (audits) already captured by Prisma Cloud's runtime sensors. It provides additional context when trying to identify the root cause of an incident.

"
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> Forensics tab. 

If "Forensics data collection" is disabled, this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> System >> Forensics tab. 

Set "Forensics data collection" to "enabled".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56980r840420_chk'
  tag severity: 'medium'
  tag gid: 'V-253528'
  tag rid: 'SV-253528r840422_rule'
  tag stig_id: 'CNTR-PC-000260'
  tag gtitle: 'SRG-APP-000099-CTR-000190'
  tag fix_id: 'F-56931r840421_fix'
  tag satisfies: ['SRG-APP-000099-CTR-000190', 'SRG-APP-000409-CTR-000990']
  tag 'documentable'
  tag cci: ['CCI-000134', 'CCI-002884']
  tag nist: ['AU-3 e', 'MA-4 (1) (a)']
end

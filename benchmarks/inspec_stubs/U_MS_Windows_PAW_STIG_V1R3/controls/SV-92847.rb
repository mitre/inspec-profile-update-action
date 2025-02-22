control 'SV-92847' do
  title 'Administrators of high-value IT resources must complete required training.'
  desc 'Required training helps to mitigate the risk of administrators not following required procedures. High-value IT resources are the most important and critical IT resources within an organization. They contain the most sensitive data in an organization, perform the most critical tasks of an organization, or have access to and can control all or nearly all IT resources within an organization. Requiring a PAW used exclusively for remote administrative management of designated high-value IT resources, including servers, workstations, directory services, applications, databases, and network components, will provide a separate "channel" for the performance of administrative tasks on high-value IT resources and isolate these functions from the majority of threats and attack vectors found on higher-risk standard client systems. A main security architectural construct of a PAW is to remove non-administrative applications and functions from the PAW. Technical controls for securing high-value IT resources will be ineffective if administrators are not aware of key security requirements.'
  desc 'check', "Review site training records and verify the organization's system administrators of high-value IT resources have received the following initial and annual training:

- Remotely manage high-value IT resources only via a PAW.
- Administrative accounts will not be used for non-administrative functions (for example, read email, browse Internet).

If required training has not been completed by the organization's system administrators of high-value IT resources, this is a finding."
  desc 'fix', 'Add the following topics to initial and annual update training modules for system administrators of high-value IT resources:

- Remotely manage high-value IT resources only via a PAW.
- Administrative accounts will not be used for non-administrative functions (for example, read email, browse Internet).'
  impact 0.3
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77707r1_chk'
  tag severity: 'low'
  tag gid: 'V-78141'
  tag rid: 'SV-92847r1_rule'
  tag stig_id: 'WPAW-00-000100'
  tag gtitle: 'PAW-00-000100'
  tag fix_id: 'F-84863r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000101']
  tag nist: ['AT-1 a 1 (a)']
end

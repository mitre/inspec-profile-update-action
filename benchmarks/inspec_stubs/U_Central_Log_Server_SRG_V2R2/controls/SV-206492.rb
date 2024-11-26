control 'SV-206492' do
  title 'The Central Log Server must be configured to send an immediate alert to the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated log record storage volume reaches 75 percent of the repository maximum log record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 

Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', "Note: This is not applicable (NA) if an external application or operating system manages this function.

Examine the configuration.

Verify the system is configured to send an immediate warning to the SA and ISSO (at a minimum) when allocated log record storage volume reaches 75 percent of the repository's maximum log record storage capacity.

If the Central Log Server is not configured to send an immediate alert to the SA and ISSO (at a minimum) when allocated log record storage volume reaches 75 percent of repository maximum log record storage capacity, this is a finding."
  desc 'fix', 'Configure the Central Log Server to send an immediate alert to the SA, ISSO, and other authorized personnel when allocated log record storage volume reaches 75 percent of repository maximum log record storage capacity.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6752r285717_chk'
  tag severity: 'low'
  tag gid: 'V-206492'
  tag rid: 'SV-206492r855299_rule'
  tag stig_id: 'SRG-APP-000359-AU-000120'
  tag gtitle: 'SRG-APP-000359'
  tag fix_id: 'F-6752r285718_fix'
  tag 'documentable'
  tag legacy: ['SV-95861', 'V-81147']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end

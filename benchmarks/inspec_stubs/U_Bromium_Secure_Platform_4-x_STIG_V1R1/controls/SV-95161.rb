control 'SV-95161' do
  title 'The Bromium Enterprise Controller (BEC) must be configured to provide report generation that supports on-demand reporting requirements for threat events.'
  desc "The report generation function must support on-demand review and analysis to facilitate the organization's ability to generate incident reports as needed to better handle larger-scale or more complex security incidents. 

On-demand reporting allows personnel to report issues more rapidly to more effectively meet reporting requirements. Collecting log data and aggregating it to present the data in a single, consolidated report achieves this objective."
  desc 'check', 'Examine the site System Security Plan (SSP) or other appropriate documentation. Verify there is a documented procedure for when security incident reports need to be exported. 

From a web browser, log on to the Bromium Enterprise Controller.

Upon successful authentication, on-demand reports for all threats are available throughout the administrator interface. 

If a procedure does not exist for providing on-demand reports for threat events, this is a finding.'
  desc 'fix', 'From a web browser, log on to the Bromium Enterprise Controller.

Upon successful authentication, the Dashboard View is the default view displayed. Select ad hoc reports based on SSP or other documented organizational requirements for reporting.

Reports can be in the form of screen output or ".csv" files.'
  impact 0.3
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80129r1_chk'
  tag severity: 'low'
  tag gid: 'V-80457'
  tag rid: 'SV-95161r1_rule'
  tag stig_id: 'BROM-00-000815'
  tag gtitle: 'SRG-APP-000367'
  tag fix_id: 'F-87263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001879']
  tag nist: ['AU-7 a']
end

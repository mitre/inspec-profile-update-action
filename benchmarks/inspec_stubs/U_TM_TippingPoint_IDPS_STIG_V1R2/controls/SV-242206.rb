control 'SV-242206' do
  title 'The site must register with the Trend Micro TippingPoint Threat Management Center (TMC) in order to receive alerts on threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected which indicate a compromise or potential for compromise.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'The ISSM and ISSO must be registered to receive updates from the TMC site. If not, this is a finding.'
  desc 'fix', '1. Navigate to https://tmc.tippingpoint.com/TMC/ 
2. Click "Create account". 
3. Enter all required data ensuring that the Client ID, Device Certificate Number, and/or Access Code is added. 
4. Click "Submit".'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45481r710159_chk'
  tag severity: 'medium'
  tag gid: 'V-242206'
  tag rid: 'SV-242206r710161_rule'
  tag stig_id: 'TIPP-IP-000440'
  tag gtitle: 'SRG-NET-000392-IDPS-00215'
  tag fix_id: 'F-45439r710160_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end

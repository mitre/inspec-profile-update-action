control 'SV-214491' do
  title 'The application pools rapid fail protection for each IIS 8.5 website must be enabled.'
  desc 'Rapid fail protection is a feature that interrogates the health of worker processes associated with websites and web applications. It can be configured to perform a number of actions such as shutting down and restarting worker processes that have reached failure thresholds. By not setting rapid fail protection the web server could become unstable in the event of a worker process crash potentially leaving the web server unusable.'
  desc 'check', 'If this IIS 8.5 installation is supporting Microsoft Exchange, and not otherwise hosting any content, this requirement is Not Applicable.

Open the IIS 8.5 Manager.

Click the "Application Pools".

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and verify the value for "Enabled" is set to "True".

If the "Rapid Fail Protection:Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the "Application Pools".

Perform for each Application Pool.

Highlight an Application Pool to review and click "Advanced Settings" in the "Actions" pane.

Scroll down to the "Rapid Fail Protection" section and set the value for "Enabled" to "True".

Click "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15700r766893_chk'
  tag severity: 'medium'
  tag gid: 'V-214491'
  tag rid: 'SV-214491r766895_rule'
  tag stig_id: 'IISW-SI-000258'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15698r766894_fix'
  tag 'documentable'
  tag legacy: ['SV-91575', 'V-76879']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

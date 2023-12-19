control 'SV-218785' do
  title 'The enhanced logging for the IIS 10.0 web server must be enabled and capture all user and web server events.'
  desc 'Log files are a critical component to the successful management of an IS used within the DoD. By generating log files with useful information, web administrators can leverage them in the event of a disaster, malicious attack, or other site specific needs.

Ascertaining the correct order of the events that occurred is important during forensic analysis. Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence. By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Click "Select Fields", verify at a minimum the following fields are checked: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

If not, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Click the "Logging" icon.

Under Format select "W3C".

Select the following fields: Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer.

Under the "Actions" pane, click "Apply".'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20257r310830_chk'
  tag severity: 'medium'
  tag gid: 'V-218785'
  tag rid: 'SV-218785r561041_rule'
  tag stig_id: 'IIST-SV-000102'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag fix_id: 'F-20255r310831_fix'
  tag satisfies: ['SRG-APP-000092-WSR-000055', 'SRG-APP-000093-WSR-000053', 'SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000097-WSR-000059']
  tag 'documentable'
  tag legacy: ['SV-109209', 'V-100105']
  tag cci: ['CCI-001462', 'CCI-001464', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133']
  tag nist: ['AU-14 (2)', 'AU-14 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d']
end

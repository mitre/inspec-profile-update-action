control 'SV-218741' do
  title 'The IIS 10.0 website must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 website events.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Ascertaining the success or failure of an event is important during forensic analysis. Correctly determining the outcome will add information to the overall reconstruction of the loggable event. By determining the success or failure of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the event occurred in other areas within the enterprise.

Without sufficient information establishing the success or failure of the logged event, investigation into the cause of event is severely hindered. The success or failure also provides a means to measure the impact of an event and help authorized personnel to determine the appropriate response. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Select the website being reviewed.

Under "IIS", double-click the "Logging" icon.

Verify the "Format:" under "Log File" is configured to "W3C".

Select "Fields".

Under "Custom Fields", verify the following fields are selected:

Request Header >> Connection

Request Header >> Warning

If any of the above fields are not selected, this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Select the website being reviewed.

Under "IIS", double-click the "Logging" icon.

Configure the "Format:" under "Log File" to "W3C".

Select "Fields".

Under "Custom Fields", select the following fields:

Request Header >> Connection

Request Header >> Warning

Click "OK".

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20214r311121_chk'
  tag severity: 'medium'
  tag gid: 'V-218741'
  tag rid: 'SV-218741r558649_rule'
  tag stig_id: 'IIST-SI-000209'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag fix_id: 'F-20212r311122_fix'
  tag 'documentable'
  tag legacy: ['SV-109307', 'V-100203']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

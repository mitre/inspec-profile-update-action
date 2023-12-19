control 'SV-221598' do
  title 'Collection of WebRTC event logs must be disabled.'
  desc "If the policy is set to “true”, Google Chrome is allowed to collect WebRTC event logs from Google services (e.g., Google Meet), and upload those logs to Google.
If the policy is set to “false”, or is unset, Google Chrome may not collect nor upload such logs.
These logs contain diagnostic information helpful when debugging issues with audio or video calls in Chrome, such as the time and size of sent and received RTP packets, feedback about congestion on the network, and metadata about time and quality of audio and video frames. These logs do not contain audio or video contents from the call.
This data collection by Chrome can only be triggered by Google's web services, such as Google Hangouts or Google Meet."
  desc 'check', 'Universal method:
1. In the omnibox (address bar) type chrome://policy
2. If "WebRtcEventLogCollectionAllowed" is not displayed under the “Policy Name” column or it is not set to "0" under the “Policy Value” column, this is a finding.
Windows method:
1. Start regedit
2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
3. If the "WebRtcEventLogCollectionAllowed" value name does not exist or its value data is not set to "0," this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with gpedit.msc
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
Policy Name: Allow collection of WebRTC event logs from Google services
Policy State: Disabled
Policy Value: NA'
  impact 0.5
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-23313r415921_chk'
  tag severity: 'medium'
  tag gid: 'V-221598'
  tag rid: 'SV-221598r615937_rule'
  tag stig_id: 'DTBC-0067'
  tag gtitle: 'SRG-APP-000206'
  tag fix_id: 'F-23302r415922_fix'
  tag 'documentable'
  tag legacy: ['SV-101305', 'V-91205']
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end

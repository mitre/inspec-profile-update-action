control 'SV-257217' do
  title 'The macOS system must only allow applications with a valid digital signature to run.'
  desc 'Gatekeeper settings must be configured correctly to only allow the system to run applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.'
  desc 'check', %q(Verify the macOS system is configured to only allow applications with a valid digital signature with the following commands:

/usr/sbin/system_profiler SPApplicationsDataType | /usr/bin/grep -B 3 -A 4 -e "Obtained from: Unknown" | /usr/bin/grep -v -e "Location: /Library/Application Support/Script Editor/Templates" -e "Location: /System/Library/" | /usr/bin/awk -F "Location: " '{print $2}' | /usr/bin/sort -u

If any results are returned and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify only applications with a valid digital signature are allowed to run:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E "(EnableAssessment | AllowIdentifiedDevelopers)"

If the result is not as follows, this is a finding.

"AllowIdentifiedDevelopers = 1;
EnableAssessment = 1;")
  desc 'fix', 'Configure the macOS system to only allow applications with a valid digital signature by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60902r905282_chk'
  tag severity: 'medium'
  tag gid: 'V-257217'
  tag rid: 'SV-257217r905284_rule'
  tag stig_id: 'APPL-13-002060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60843r905283_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

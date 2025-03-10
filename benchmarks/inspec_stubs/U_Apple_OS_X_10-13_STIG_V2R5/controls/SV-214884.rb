control 'SV-214884' do
  title 'The macOS system must allow only applications that have a valid digital signature to run.'
  desc 'Gatekeeper settings must be configured correctly to only allow the system to run applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.'
  desc 'check', %q(Identify any unsigned applications that have been installed on the system:
/usr/sbin/system_profiler SPApplicationsDataType | /usr/bin/grep -B 3 -A 4 -e "Obtained from: Unknown" | /usr/bin/grep -v -e "Location: /Library/Application Support/Script Editor/Templates" -e "Location: /System/Library/" | /usr/bin/awk -F "Location: " '{print $2}' | /usr/bin/sort -u

If any results are returned and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify only applications with a valid digital signature are allowed to run:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(EnableAssessment | AllowIdentifiedDevelopers)’

If the return is null, or is not:
AllowIdentifiedDevelopers = 1;
EnableAssessment = 1;
This is a finding.)
  desc 'fix', 'This setting is enforced using the "Security and Privacy Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16084r648719_chk'
  tag severity: 'medium'
  tag gid: 'V-214884'
  tag rid: 'SV-214884r648720_rule'
  tag stig_id: 'AOSX-13-000710'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-16082r397225_fix'
  tag 'documentable'
  tag legacy: ['SV-96361', 'V-81647']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

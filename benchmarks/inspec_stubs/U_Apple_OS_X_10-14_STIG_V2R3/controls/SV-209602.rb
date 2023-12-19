control 'SV-209602' do
  title 'The macOS system must allow only applications that have a valid digital signature to run.'
  desc 'Gatekeeper settings must be configured correctly to only allow the system to run applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.'
  desc 'check', %q(Identify any unsigned applications that have been installed on the system:
/usr/sbin/system_profiler SPApplicationsDataType | /usr/bin/grep -B 3 -A 4 -e "Obtained from: Unknown" | /usr/bin/grep -v -e "Location: /Library/Application Support/Script Editor/Templates" -e "Location: /System/Library/" | /usr/bin/awk -F "Location: " '{print $2}' | /usr/bin/sort -u

If any results are returned and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Verify only applications with a valid digital signature are allowed to run:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(EnableAssessment | AllowIdentifiedDevelopers)'

If the return is null, or is not the following, this is a finding:
 AllowIdentifiedDevelopers = 1;
 EnableAssessment = 1;)
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9853r648721_chk'
  tag severity: 'medium'
  tag gid: 'V-209602'
  tag rid: 'SV-209602r648722_rule'
  tag stig_id: 'AOSX-14-002060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9853r282289_fix'
  tag 'documentable'
  tag legacy: ['V-95943', 'SV-105081']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-90773' do
  title 'The OS X system must allow only applications downloaded from the App Store or properly signed to run.'
  desc 'Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the OS X to verify that the application has not been modified by a malicious third party.'
  desc 'check', 'To verify only applications downloaded from the App Store are allowed to run, type the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep EnableAssessment

If "EnableAssessment" is not set to "1", this is a finding.

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep AllowIdentifiedDevelopers

If "AllowIdentifiedDevelopers" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Security and Privacy Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76085'
  tag rid: 'SV-90773r2_rule'
  tag stig_id: 'AOSX-12-000710'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-82723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

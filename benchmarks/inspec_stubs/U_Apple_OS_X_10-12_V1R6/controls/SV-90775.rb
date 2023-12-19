control 'SV-90775' do
  title 'The OS X system must be configured so that end users cannot override Gatekeeper settings.'
  desc 'Gatekeeper must be configured with a configuration profile to prevent normal users from overriding its setting. If users are allowed to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system. Gatekeeper is a security feature that ensures applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow Mac OS X to verify the application has not been modified by a malicious third party.'
  desc 'check', 'To verify the user cannot override Gatekeeper settings, type the following code:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableOverride

If "DisableOverride" is not set to "1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Security and Privacy Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76087'
  tag rid: 'SV-90775r1_rule'
  tag stig_id: 'AOSX-12-000711'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82725r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

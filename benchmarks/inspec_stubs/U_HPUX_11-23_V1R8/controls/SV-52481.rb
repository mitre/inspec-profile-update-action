control 'SV-52481' do
  title 'During a password change, the system must determine if password aging attributes are inherited from the /etc/default/security file attributes when no password aging is specified in the shadow file for local users.'
  desc 'Password aging attributes are stored in /etc/default/security and /etc/shadow. Anytime a password aging policy is changed, policy requirements are updated in /etc/default/security. If the system is allowed to override or ignore updates made to /etc/default/security, deprecated password aging policies will remain intact and never enforce newer requirements.'
  desc 'check', 'For Trusted Mode:
If the system is operating in Trusted Mode, this check is not applicable.

For SMSE:
Check the OVERRIDE_SYSDEF_PWAGE attribute setting.
# grep OVERRIDE_SYSDEF_PWAGE /etc/default/security

If the OVERRIDE_SYSDEF_PWAGE attribute is missing or not set to 0, this is a finding.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) to update the OVERRIDE_SYSDEF_PWAGE attribute. See the below example:
OVERRIDE_SYSDEF_PWAGE=0

Note: If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-47028r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40492'
  tag rid: 'SV-52481r1_rule'
  tag stig_id: 'GEN000000-HPUX0450'
  tag gtitle: 'GEN000000-HPUX0450'
  tag fix_id: 'F-45441r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

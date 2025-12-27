control 'SV-52330' do
  title 'userdb database must not be used to override the system-wide variables in the security file, unless required.'
  desc 'The user database stores per-user information. It consists of the /var/adm/userdb directory and the files within it. A per-user value in /var/adm/userdb will override any corresponding system-wide default configured in the /etc/default/security file. Allowing per-user files to relax system-wide security settings creates potential security gaps that can compromise overall system security.'
  desc 'check', 'If the system is operating in Trusted Mode, this check is not applicable.

For SMSE:
Check the /var/adm/userdb database for individual user settings: 
# /usr/sbin/userdbget -a

If the “userdb” database is used exclusively to enhance/tighten the security requirements as defined in the /etc/default/security file (see the following example), this is not a finding.
Example: /etc/default/security requires a MIN_PASSWORD_LENGTH attribute setting of N=14 and specific per user attribute values in /var/adm/userdb are set to 15.

If any user information is returned that is greater than the required attribute setpoint in the/etc/default/security file (see the following example), this is a finding.
Example: /etc/default/security requires a MIN_PASSWORD_LENGTH attribute setting of N=14 and specific per user attribute values in /var/adm/userdb are set to 13.'
  desc 'fix', 'If the system is operating in Trusted Mode, no fix is required.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Delete any configured users from the /var/adm/userdb database:
# /usr/sbin/userdbset -d -u <user>

Restart auditing:
# /sbin/init.d/auditing stop
# /sbin/init.d/auditing start'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-46983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40350'
  tag rid: 'SV-52330r1_rule'
  tag stig_id: 'GEN000000-HPUX0200'
  tag gtitle: 'GEN000000-HPUX0200'
  tag fix_id: 'F-45321r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

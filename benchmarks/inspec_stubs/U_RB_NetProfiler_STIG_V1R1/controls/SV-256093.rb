control 'SV-256093' do
  title 'The Riverbed NetProfiler must be configured to use an authentication server to authenticate users prior to granting administrative access.'
  desc "Centralized management of authentication settings increases the security of remote and nonlocal access methods. This control is particularly important protection against the insider threat. With robust centralized management, audit records for administrator account access to the organization's network devices can be more readily analyzed for trends and anomalies. The alternative method of defining administrator accounts on each device exposes the device configuration to remote access authentication attacks and system administrators with multiple authenticators for each network device."
  desc 'check', 'Go to Administration >> Account Management >> Remote Authentication. 

Verify that RADIUS, TACACS+, or SAML 2.0 are enabled and configured. 

If this is not true, this is a finding.'
  desc 'fix', "This requirement does not apply to the local account of last resort or system accounts.

Go to Administration >> Account Management >> Remote Authentication. 

Configure and enable RADIUS, TACACS+, or SAML 2.0.

The following is an example using RADIUS. Refer to the user's guide for instructions for TACACS+ or SAML."
  impact 0.7
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59767r882785_chk'
  tag severity: 'high'
  tag gid: 'V-256093'
  tag rid: 'SV-256093r882787_rule'
  tag stig_id: 'RINP-DM-000060'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-59710r882786_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end

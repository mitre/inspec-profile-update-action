control 'SV-82887' do
  title 'The Mainframe Product must prohibit the use of cached authenticators after one hour.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to prohibit the use of cached authenticators after one hour, this is not a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to prohibit the use of cached authenticators after one hour.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68397'
  tag rid: 'SV-82887r1_rule'
  tag stig_id: 'SRG-APP-000400-MFP-000241'
  tag gtitle: 'SRG-APP-000400-MFP-000241'
  tag fix_id: 'F-74513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

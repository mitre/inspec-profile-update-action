control 'SV-29548' do
  title 'DOD information system access does not require the use of a password.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources within the same administrative domain.'
  desc 'fix', 'Configure all DoD information systems to require passwords to gain access.

The password required flag can be set by entering the following on a command line: “Net user <account_name> /passwordreq:yes”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-7002'
  tag rid: 'SV-29548r1_rule'
  tag gtitle: 'Password Requirement'
  tag fix_id: 'F-6581r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'For a DISABLED account(s) with a blank or null password, classify/downgrade this finding to a Severity Code 2 finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

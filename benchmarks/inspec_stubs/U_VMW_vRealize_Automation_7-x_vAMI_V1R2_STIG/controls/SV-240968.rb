control 'SV-240968' do
  title 'The application server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the application server, the client sends a list of supported cipher suites in order of preference. The application server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the application server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Check that FIPS mode is enabled in the vRealize Automation virtual appliance management interface with the following steps:

1. Log into the vRealize Automation virtual appliance management interface (vAMI).
     https:// vrealize-automation-appliance-FQDN:5480
2. Select vRA Settings >> Host Settings.
3. Review the button under the Actions heading on the upper right to confirm that "enable FIPS" is selected.

If "enable FIPS" is not selected, this is a finding.

Alternately, check that FIPS mode is enabled in the command line using the following steps:

1. Log into the console as root.
2. Run the command: vcac-vami fips status.

If FIPS is not enabled, this is a finding.'
  desc 'fix', 'Enable FIPS mode in the vRealize Automation virtual appliance management interface with the following steps:

1. Log into the vRealize Automation virtual appliance management interface (vAMI).
     https:// vrealize-automation-appliance-FQDN:5480
2. Select vRA Settings >> Host Settings.
3. Click the button under the Actions heading on the upper right to enable or disable FIPS.
4. Click "Yes" to restart the vRealize Automation appliance.

Alternately, enable FIPS mode in the command line using the following steps:
1. Log into the console as root.
2. Run the command: vcac-vami fips enable'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44201r878101_chk'
  tag severity: 'medium'
  tag gid: 'V-240968'
  tag rid: 'SV-240968r918128_rule'
  tag stig_id: 'VRAU-VA-000660'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-44160r878102_fix'
  tag 'documentable'
  tag legacy: ['SV-100931', 'V-90281']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end

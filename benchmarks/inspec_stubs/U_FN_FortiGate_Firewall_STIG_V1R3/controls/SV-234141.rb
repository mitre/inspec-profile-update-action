control 'SV-234141' do
  title 'The FortiGate firewall must protect traffic log records from unauthorized access while in transit to the central audit server.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or identify an improperly configured firewall. Thus, it is imperative that the collected log data be secured and access be restricted to authorized personnel. Methods of protection may include encryption or logical separation.

This does not apply to traffic logs generated on behalf of the device itself (management). Some devices store traffic logs separately from the system logs.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privileges.

1. Open a CLI console via SSH or from the GUI widget.
2. Run the following command:
     # show full-configuration log syslogd setting
The output should include:
     set server {123.123.123.123}
     set mode reliable
     set enc-algorithm {medium-high | high}

If the syslogd mode is not set to reliable, this is a finding.
If the set enc-algorithm is not set to high or medium-high, this is a finding.'
  desc 'fix', "Log in to the FortiGate GUI with Super-Admin privilege.

First, upload the CA certificate that issued the Syslog server certificate.
1. Click System.
2. Click Certificates.
3. Click Import, then CA Certificate.
4. Specify File, and click + Upload.
5. Choose the CA Certificate to upload from the local hard drive.
6. Click OK.

Then, configure a TLS-enabled syslog connection:
1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config log syslogd setting
     #    set status enable
     #    set server {SYSLOG SERVER IP ADDRESS} 
     #    set mode reliable
     #    set enc-algorithm {HIGH-MEDIUM | HIGH}
     #    set certificate (Optional - Select local certificate if Syslog server is challenging client [FortiGate] for authentication)
     # end

Note: The server IP address must be on the site's management network."
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37326r835163_chk'
  tag severity: 'medium'
  tag gid: 'V-234141'
  tag rid: 'SV-234141r835165_rule'
  tag stig_id: 'FNFG-FW-000050'
  tag gtitle: 'SRG-NET-000098-FW-000021'
  tag fix_id: 'F-37291r835164_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
